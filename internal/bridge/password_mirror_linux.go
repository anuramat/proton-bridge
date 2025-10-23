//go:build linux

// Copyright (c) 2025 Proton AG
//
// This file is part of Proton Mail Bridge.
//
// Proton Mail Bridge is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Proton Mail Bridge is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Proton Mail Bridge.  If not, see <https://www.gnu.org/licenses/>.

package bridge

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ProtonMail/proton-bridge/v3/internal/constants"
	"github.com/ProtonMail/proton-bridge/v3/pkg/algo"
	"github.com/ProtonMail/proton-bridge/v3/pkg/keychain"
	"github.com/docker/docker-credential-helpers/credentials"
)

const (
	passwordSuffix   = "imap-password"
	keychainPathBase = "protonmail/%s/users"
)

type secretServiceHelper interface {
	Add(*credentials.Credentials) error
	Delete(string) error
	List() (map[string]string, error)
}

type linuxPasswordMirror struct {
	helper secretServiceHelper
	prefix string
}

func newPasswordMirror(*Bridge) passwordMirror {
	return &linuxPasswordMirror{
		helper: &keychain.SecretServiceDBusHelper{},
		prefix: fmt.Sprintf(keychainPathBase, constants.KeyChainName),
	}
}

func (m *linuxPasswordMirror) SyncAll(passwords map[string][]byte) error {
	existing, err := m.helper.List()
	if err != nil {
		return fmt.Errorf("list credentials: %w", err)
	}

	var errs error

	for userID, pass := range passwords {
		if len(pass) == 0 {
			continue
		}

		if err := m.SyncUser(userID, pass); err != nil {
			errs = errors.Join(errs, fmt.Errorf("sync user %s: %w", userID, err))
		}
	}

	for serverURL := range existing {
		userID, ok := m.extractUser(serverURL)
		if !ok {
			continue
		}

		if _, keep := passwords[userID]; keep {
			continue
		}

		if err := m.helper.Delete(serverURL); err != nil {
			errs = errors.Join(errs, fmt.Errorf("delete stale user %s: %w", userID, err))
		}
	}

	return errs
}

func (m *linuxPasswordMirror) SyncUser(userID string, pass []byte) error {
	if len(pass) == 0 {
		return m.helper.Delete(m.serverURL(userID))
	}

	encoded := algo.B64RawEncode(pass)

	return m.helper.Add(&credentials.Credentials{
		ServerURL: m.serverURL(userID),
		Username:  userID,
		Secret:    string(encoded),
	})
}

func (m *linuxPasswordMirror) Delete(userID string) error {
	return m.helper.Delete(m.serverURL(userID))
}

func (m *linuxPasswordMirror) serverURL(userID string) string {
	return fmt.Sprintf("%s/%s/%s", m.prefix, userID, passwordSuffix)
}

func (m *linuxPasswordMirror) extractUser(serverURL string) (string, bool) {
	if !strings.HasPrefix(serverURL, m.prefix+"/") {
		return "", false
	}

	if !strings.HasSuffix(serverURL, "/"+passwordSuffix) {
		return "", false
	}

	trimmed := strings.TrimPrefix(serverURL, m.prefix+"/")
	return strings.TrimSuffix(trimmed, "/"+passwordSuffix), true
}
