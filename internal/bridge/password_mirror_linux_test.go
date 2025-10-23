//go:build linux

package bridge

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ProtonMail/proton-bridge/v3/internal/constants"
	"github.com/ProtonMail/proton-bridge/v3/pkg/algo"
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/stretchr/testify/require"
)

type recordingHelper struct {
	items   map[string]record
	addErr  map[string]error
	delErr  map[string]error
	listErr error
}

type record struct {
	username string
	secret   string
}

func newRecordingHelper() *recordingHelper {
	return &recordingHelper{
		items:  make(map[string]record),
		addErr: make(map[string]error),
		delErr: make(map[string]error),
	}
}

func (h *recordingHelper) Add(creds *credentials.Credentials) error {
	if err, ok := h.addErr[creds.ServerURL]; ok {
		return err
	}

	h.items[creds.ServerURL] = record{
		username: creds.Username,
		secret:   creds.Secret,
	}
	return nil
}

func (h *recordingHelper) Delete(serverURL string) error {
	if err, ok := h.delErr[serverURL]; ok {
		return err
	}

	delete(h.items, serverURL)
	return nil
}

func (h *recordingHelper) List() (map[string]string, error) {
	if h.listErr != nil {
		return nil, h.listErr
	}

	out := make(map[string]string, len(h.items))
	for url, rec := range h.items {
		out[url] = rec.username
	}
	return out, nil
}

func TestLinuxPasswordMirrorSyncAll(t *testing.T) {
	helper := newRecordingHelper()
	mirror := &linuxPasswordMirror{
		helper: helper,
		prefix: fmt.Sprintf(keychainPathBase, constants.KeyChainName),
	}

	// Existing stale entry should be removed.
	stale := mirror.serverURL("stale-user")
	helper.items[stale] = record{username: "stale-user", secret: "obsolete"}

	passwords := map[string][]byte{
		"user-1": []byte("pass-1"),
		"user-2": []byte("pass-2"),
	}

	require.NoError(t, mirror.SyncAll(passwords))

	require.Equal(t, record{username: "user-1", secret: string(algo.B64RawEncode([]byte("pass-1")))}, helper.items[mirror.serverURL("user-1")])
	require.Equal(t, record{username: "user-2", secret: string(algo.B64RawEncode([]byte("pass-2")))}, helper.items[mirror.serverURL("user-2")])
	_, ok := helper.items[stale]
	require.False(t, ok, "stale entry should be removed")
}

func TestLinuxPasswordMirrorSyncAllAggregatesErrors(t *testing.T) {
	helper := newRecordingHelper()
	mirror := &linuxPasswordMirror{
		helper: helper,
		prefix: fmt.Sprintf(keychainPathBase, constants.KeyChainName),
	}

	bad := mirror.serverURL("bad-user")
	helper.addErr[bad] = errors.New("add boom")
	helper.delErr[mirror.serverURL("stale")] = errors.New("delete boom")
	helper.items[mirror.serverURL("stale")] = record{username: "stale", secret: "old"}

	err := mirror.SyncAll(map[string][]byte{
		"bad-user":   []byte("xx"),
		"good-user":  []byte("yy"),
		"another-ok": []byte("zz"),
	})
	require.Error(t, err)

	// Successful entries should still be written.
	require.Equal(t, string(algo.B64RawEncode([]byte("yy"))), helper.items[mirror.serverURL("good-user")].secret)
	require.Equal(t, string(algo.B64RawEncode([]byte("zz"))), helper.items[mirror.serverURL("another-ok")].secret)

	// Failed entry should not overwrite.
	_, ok := helper.items[bad]
	require.False(t, ok)
}

func TestLinuxPasswordMirrorSyncUserDeletesOnEmpty(t *testing.T) {
	helper := newRecordingHelper()
	mirror := &linuxPasswordMirror{
		helper: helper,
		prefix: fmt.Sprintf(keychainPathBase, constants.KeyChainName),
	}

	target := mirror.serverURL("user")
	helper.items[target] = record{username: "user", secret: "old"}

	require.NoError(t, mirror.SyncUser("user", nil))
	_, ok := helper.items[target]
	require.False(t, ok)
}
