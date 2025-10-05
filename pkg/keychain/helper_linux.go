// Copyright (c) 2026 Proton AG
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
// along with Proton Mail Bridge. If not, see <https://www.gnu.org/licenses/>.

package keychain

import (
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/docker/docker-credential-helpers/pass"
	"github.com/docker/docker-credential-helpers/secretservice"
	"github.com/sirupsen/logrus"
)

const (
	Pass              = "pass-app"
	SecretService     = "secret-service"
	SecretServiceDBus = "secret-service-dbus"
)

func listHelpers() (Helpers, string) {
	helpers := make(Helpers)

	if isUsable(newDBusHelper("")) {
		helpers[SecretServiceDBus] = newDBusHelper
		logrus.WithField("keychain", "SecretServiceDBus").Info("Keychain is usable.")
	} else {
		logrus.WithField("keychain", "SecretServiceDBus").Debug("Keychain is not available.")
	}

	defaultHelper := SecretServiceDBus
	return helpers, defaultHelper
}

func newDBusHelper(string) (credentials.Helper, error) {
	return &SecretServiceDBusHelper{}, nil
}

func newPassHelper(string) (credentials.Helper, error) {
	return &pass.Pass{}, nil
}

func newSecretServiceHelper(string) (credentials.Helper, error) {
	return &secretservice.Secretservice{}, nil
}
