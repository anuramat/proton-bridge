package bridge

import (
	"context"
	"testing"

	"github.com/ProtonMail/gluon/async"
	"github.com/ProtonMail/proton-bridge/v3/internal/vault"
	"github.com/stretchr/testify/require"
)

type spyMirror struct {
	lastAll   map[string][]byte
	lastUser  string
	lastPass  []byte
	deleted   string
	allErr    error
	userErr   error
	deleteErr error
}

func (s *spyMirror) SyncAll(m map[string][]byte) error {
	s.lastAll = m
	return s.allErr
}

func (s *spyMirror) SyncUser(user string, pass []byte) error {
	s.lastUser = user
	s.lastPass = pass
	return s.userErr
}

func (s *spyMirror) Delete(user string) error {
	s.deleted = user
	return s.deleteErr
}

func makeTestVault(t *testing.T) *vault.Vault {
	t.Helper()

	base := t.TempDir()
	gluon := t.TempDir()

	key := []byte("0123456789abcdef0123456789abcdef")

	v, corrupt, err := vault.New(base, gluon, key, async.NoopPanicHandler{})
	require.NoError(t, err)
	require.Nil(t, corrupt)

	return v
}

func addVaultUser(t *testing.T, v *vault.Vault, userID, email string, pass []byte) {
	t.Helper()

	u, err := v.AddUser(userID, userID, email, "authUID", "authRef", []byte("keypass"))
	require.NoError(t, err)
	defer func() { _ = u.Close() }()

	if pass != nil {
		require.NoError(t, u.SetBridgePass(pass))
	}
}

func TestBridgeMirrorSyncAllCollectsVaultPasswords(t *testing.T) {
	v := makeTestVault(t)
	addVaultUser(t, v, "user-1", "user1@example.com", []byte("pass-1"))
	addVaultUser(t, v, "user-2", "user2@example.com", []byte("pass-2"))

	spy := &spyMirror{}
	bridge := &Bridge{
		vault:          v,
		passwordMirror: spy,
	}

	bridge.mirrorSyncAll("test")

	require.Len(t, spy.lastAll, 2)
	require.Equal(t, []byte("pass-1"), spy.lastAll["user1@example.com"])
	require.Equal(t, []byte("pass-2"), spy.lastAll["user2@example.com"])
}

func TestBridgeMirrorSyncUserAndDelete(t *testing.T) {
	v := makeTestVault(t)
	addVaultUser(t, v, "user", "user@example.com", []byte("secret"))

	spy := &spyMirror{}
	bridge := &Bridge{
		vault:          v,
		passwordMirror: spy,
	}

	bridge.mirrorSyncUser("user", []byte("secret"), "reason")
	require.Equal(t, "user@example.com", spy.lastUser)
	require.Equal(t, []byte("secret"), spy.lastPass)

	bridge.mirrorDeleteUser("user@example.com", "reason")
	require.Equal(t, "user@example.com", spy.deleted)
}

func TestBridgeMirrorSyncAllHandlesMirrorError(t *testing.T) {
	v := makeTestVault(t)
	addVaultUser(t, v, "user", "user@example.com", []byte("pass"))

	spy := &spyMirror{allErr: context.DeadlineExceeded}
	bridge := &Bridge{
		vault:          v,
		passwordMirror: spy,
	}

	bridge.mirrorSyncAll("test") // ensures error path gracefully handled
}
