package cipher

import (
	"net"
	"time"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type Method interface {
	DialConn(conn net.Conn, destination M.Socksaddr) (net.Conn, error)
	DialEarlyConn(conn net.Conn, destination M.Socksaddr) net.Conn
	DialPacketConn(conn net.Conn) N.NetPacketConn
}

type MethodOptions struct {
	Password string
	Key      []byte
	KeyList  [][]byte
	TimeFunc func() time.Time
	// PrefixSalt is an optional fixed prefix for AEAD salts (Outline-style).
	// The salt length is unchanged: salt = PrefixSalt || random bytes.
	// Only used by the shadowaead methods.
	PrefixSalt []byte
}

type MethodCreator func(methodName string, options MethodOptions) (Method, error)
