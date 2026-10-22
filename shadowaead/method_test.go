package shadowaead

import (
	"bytes"
	"io"
	"net"
	"testing"

	C "github.com/metacubex/sing-shadowsocks2/cipher"
	"github.com/metacubex/sing-shadowsocks2/internal/legacykey"
	M "github.com/metacubex/sing/common/metadata"
)

// dialSalt performs DialConn over net.Pipe and returns the first n bytes written to the wire.
func dialSalt(t *testing.T, method *Method, n int) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()

	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := method.DialConn(client, M.ParseSocksaddr("example.com:80"))
		done <- result{conn, err}
	}()

	salt := make([]byte, n)
	if _, err := io.ReadFull(server, salt); err != nil {
		t.Fatal(err)
	}
	// drain the remainder of the request so DialConn can finish
	go io.Copy(io.Discard, server)

	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	r.conn.Close()
	return salt
}

func TestPrefixSalt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		prefix []byte
	}{
		{"aes-128-gcm", "aes-128-gcm", []byte("POST ")},
		{"aes-256-gcm", "aes-256-gcm", []byte{0x16, 0x03, 0x01, 0x02}},
		{"chacha20", "chacha20-ietf-poly1305", []byte("HTTP/1.1 ")},
		{"max-prefix", "aes-128-gcm", bytes.Repeat([]byte{0xAA}, 15)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NewMethod(tc.method, C.MethodOptions{Password: "test", PrefixSalt: tc.prefix})
			if err != nil {
				t.Fatal(err)
			}
			salt1 := dialSalt(t, m, m.keySaltLength)
			salt2 := dialSalt(t, m, m.keySaltLength)
			if len(salt1) != m.keySaltLength || len(salt2) != m.keySaltLength {
				t.Fatal("unexpected salt length")
			}
			if !bytes.Equal(salt1[:len(tc.prefix)], tc.prefix) || !bytes.Equal(salt2[:len(tc.prefix)], tc.prefix) {
				t.Fatalf("salt does not start with prefix: %x, %x", salt1, salt2)
			}
			if bytes.Equal(salt1[len(tc.prefix):], salt2[len(tc.prefix):]) {
				t.Fatal("salt tail is not random")
			}
		})
	}
}

func TestNoPrefixSalt(t *testing.T) {
	m, err := NewMethod("aes-128-gcm", C.MethodOptions{Password: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.prefixSalt) != 0 {
		t.Fatal("prefix must be empty by default")
	}
	salt1 := dialSalt(t, m, m.keySaltLength)
	salt2 := dialSalt(t, m, m.keySaltLength)
	if bytes.Equal(salt1, salt2) {
		t.Fatal("salt is not random")
	}
}

// TestPrefixSaltRoundTrip checks that the server side, which derives the key from the
// full salt (prefix included), can decrypt the request.
func TestPrefixSaltRoundTrip(t *testing.T) {
	prefix := []byte("POST ")
	m, err := NewMethod("aes-128-gcm", C.MethodOptions{Password: "test", PrefixSalt: prefix})
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		conn, err := m.DialConn(client, M.ParseSocksaddr("example.com:80"))
		if err == nil {
			conn.Close()
		}
	}()
	// Server uses a method without prefix: it must still accept any salt.
	sm, err := NewMethod("aes-128-gcm", C.MethodOptions{Password: "test"})
	if err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, sm.keySaltLength)
	if _, err = io.ReadFull(server, salt); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(salt, prefix) {
		t.Fatalf("missing prefix: %x", salt)
	}
	key := make([]byte, sm.keySaltLength)
	legacykey.Kdf(sm.key, salt, key)
	aead, err := sm.constructor(key)
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 2+aead.Overhead())
	if _, err = io.ReadFull(server, header); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	lengthBytes, err := aead.Open(nil, nonce, header, nil)
	if err != nil {
		t.Fatalf("server failed to decrypt with full-salt KDF: %v", err)
	}
	if len(lengthBytes) != 2 {
		t.Fatal("bad length chunk")
	}
}

func TestPrefixSaltTooLong(t *testing.T) {
	for _, tc := range []struct {
		method string
		length int
	}{
		{"aes-128-gcm", 16},
		{"aes-128-gcm", 17},
		{"aes-256-gcm", 32},
	} {
		_, err := NewMethod(tc.method, C.MethodOptions{Password: "test", PrefixSalt: make([]byte, tc.length)})
		if err == nil {
			t.Fatalf("%s: expected error for prefix length %d", tc.method, tc.length)
		}
	}
}
