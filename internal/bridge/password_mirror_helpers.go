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
	"fmt"

	"github.com/ProtonMail/proton-bridge/v3/internal/vault"
)

func (bridge *Bridge) mirrorSyncAll(reason string) {
	if bridge.passwordMirror == nil {
		return
	}

	passwords, err := bridge.collectVaultPasswords()
	if err != nil {
		logPkg.WithError(err).Warn("Failed to collect vault passwords for Secret Service sync")
		return
	}

	if err := bridge.passwordMirror.SyncAll(passwords); err != nil {
		logPkg.WithError(err).Warnf("Failed to mirror IMAP passwords to Secret Service (%s)", reason)
	}
}

func (bridge *Bridge) mirrorSyncUser(userID string, password []byte, reason string) {
	if bridge.passwordMirror == nil {
		return
	}

	identifier, err := bridge.mirrorIdentifier(userID)
	if err != nil {
		logPkg.WithError(err).Warnf("Failed to resolve mirror identifier for user %s", userID)
	}

	if err := bridge.passwordMirror.SyncUser(identifier, password); err != nil {
		logPkg.WithError(err).Warnf("Failed to mirror IMAP password for user %s (%s)", userID, reason)
	}
}

func (bridge *Bridge) mirrorDeleteUser(identifier, reason string) {
	if bridge.passwordMirror == nil {
		return
	}

	if identifier == "" {
		return
	}

	if err := bridge.passwordMirror.Delete(identifier); err != nil {
		logPkg.WithError(err).Warnf("Failed to delete Secret Service entry for %s (%s)", identifier, reason)
	}
}

func (bridge *Bridge) collectVaultPasswords() (map[string][]byte, error) {
	if bridge.vault == nil {
		return nil, fmt.Errorf("vault unavailable")
	}

	passwords := make(map[string][]byte)

	for _, userID := range bridge.vault.GetUserIDs() {
		if err := bridge.vault.GetUser(userID, func(user *vault.User) {
			if pass := user.BridgePass(); len(pass) > 0 {
				key := mirrorIdentifierFromVaultUser(user)
				passwords[key] = append([]byte(nil), pass...)
			}
		}); err != nil {
			return nil, fmt.Errorf("get user %s: %w", userID, err)
		}
	}

	return passwords, nil
}

func (bridge *Bridge) mirrorIdentifier(userID string) (string, error) {
	if bridge.vault == nil {
		return userID, fmt.Errorf("vault unavailable")
	}

	var identifier string
	if err := bridge.vault.GetUser(userID, func(user *vault.User) {
		identifier = mirrorIdentifierFromVaultUser(user)
	}); err != nil {
		return userID, fmt.Errorf("get user %s: %w", userID, err)
	}

	if identifier == "" {
		identifier = userID
	}

	return identifier, nil
}

func mirrorIdentifierFromVaultUser(user *vault.User) string {
	if email := user.PrimaryEmail(); email != "" {
		return email
	}

	if username := user.Username(); username != "" {
		return username
	}

	return user.UserID()
}
