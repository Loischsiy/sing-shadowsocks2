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
	// PrefixSalt is an optional fixed prefix for TCP (stream) AEAD salts (Outline-style).
	// The salt length is unchanged: salt = PrefixSalt || random bytes.
	// Only used by the shadowaead methods.
	PrefixSalt []byte
	// PrefixSaltUDP is the same as PrefixSalt but for UDP packets. It is configured
	// separately because a good TCP prefix is usually a bad UDP prefix.
	// PrefixSalt is NOT applied to UDP. Only used by the shadowaead methods.
	PrefixSaltUDP []byte
}

type MethodCreator func(methodName string, options MethodOptions) (Method, error)
