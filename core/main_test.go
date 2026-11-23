package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/crypto/curve25519"
)

func testKey(t *testing.T) ([]byte, []byte) {
	t.Helper()
	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		t.Fatal(err)
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return private, public
}

func TestParseClientConfig(t *testing.T) {
	private, public := testKey(t)
	text := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.77.0.2/32\nS1 = 16\nS2 = 16\nS3 = 16\nS4 = 16\nHeaderProtectionKey = %s\nContentPaddingAddition = 0-12\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:43798\nAllowedIPs = 0.0.0.0/0\n", base64.StdEncoding.EncodeToString(private), base64.StdEncoding.EncodeToString(private), base64.StdEncoding.EncodeToString(public))
	parsed, err := parseConfig(text)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"header_protection_key=" + hex.EncodeToString(private), "content_padding_addition=0-12", "endpoint=127.0.0.1:43798", "allowed_ip=::/0"} {
		if !strings.Contains(parsed.uapi, field) {
			t.Fatalf("Missing %s", field)
		}
	}
	if _, err = parseConfig(text + "\n[Peer]\nPublicKey = invalid\n"); err == nil {
		t.Fatal("Multiple peers accepted")
	}
	if _, err = parseConfig(strings.Replace(text, "PrivateKey = "+base64.StdEncoding.EncodeToString(private), "PrivateKey = invalid", 1)); err == nil {
		t.Fatal("Invalid key accepted")
	}
}

func vpnPair(t *testing.T) (*netstack.Net, *netstack.Net) {
	t.Helper()
	aPriv, aPub := testKey(t)
	bPriv, bPub := testKey(t)
	reserve := func() int {
		u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		p := u.LocalAddr().(*net.UDPAddr).Port
		u.Close()
		return p
	}
	ap, bp := reserve(), reserve()
	makeDevice := func(ip string, private, public []byte, port, peerPort int) *netstack.Net {
		tun, network, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(ip)}, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, 1280)
		if err != nil {
			t.Fatal(err)
		}
		dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "test: "))
		uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\ns1=16\ns2=16\ns3=16\ns4=16\nheader_protection_key=%s\ncontent_padding_addition=0-16\nrandom_trailers=true\nh1=1234567\nh2=2345678\nh3=3456789\nh4=4567890\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\n", hex.EncodeToString(private), port, hex.EncodeToString(aPriv), hex.EncodeToString(public), peerPort)
		if err = dev.IpcSet(uapi); err != nil {
			t.Fatal(err)
		}
		if err = dev.Up(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(dev.Close)
		return network
	}
	return makeDevice("10.77.0.2", aPriv, bPub, ap, bp), makeDevice("10.77.0.1", bPriv, aPub, bp, ap)
}

func openSOCKS(t *testing.T, listener net.Listener, command byte, targetPort int) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(15 * time.Second))
	c.Write([]byte{5, 1, 0})
	var greeting [2]byte
	if _, err = io.ReadFull(c, greeting[:]); err != nil {
		t.Fatal(err)
	}
	if greeting != [2]byte{5, 0} {
		t.Fatalf("SOCKS greeting: %v", greeting)
	}
	c.Write([]byte{5, command, 0, 1, 10, 77, 0, 1, byte(targetPort >> 8), byte(targetPort)})
	return c
}

func TestTunnelTCPAndUDP(t *testing.T) {
	clientNet, serverNet := vpnPair(t)
	tcp, err := serverNet.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.1:18080"))
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		c, err := tcp.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()
	udp, err := serverNet.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.1:18081"))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 2048)
		n, from, err := udp.ReadFrom(b)
		if err == nil {
			udp.WriteTo(b[:n], from)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go serve(ctx, listener, clientNet)
	t.Run("TCP", func(t *testing.T) {
		c := openSOCKS(t, listener, 1, 18080)
		var response [10]byte
		if _, err := io.ReadFull(c, response[:]); err != nil {
			t.Fatal(err)
		}
		if response[1] != 0 {
			t.Fatalf("SOCKS connect failed: %v", response)
		}
		// Exercise a response spanning many MTU-sized packets, as an HTTPS page does.
		message := bytes.Repeat([]byte("Tiho through a real AmneziaWG encrypted tunnel"), 8192)
		written := make(chan error, 1)
		go func() { _, err := c.Write(message); written <- err }()
		got := make([]byte, len(message))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatal(err)
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, message) {
			t.Fatal("TCP payload mismatch")
		}
	})
	t.Run("UDP", func(t *testing.T) {
		c := openSOCKS(t, listener, 3, 0)
		var response [10]byte
		if _, err := io.ReadFull(c, response[:]); err != nil {
			t.Fatal(err)
		}
		if response[1] != 0 {
			t.Fatalf("UDP associate failed: %v", response)
		}
		relay := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(binary.BigEndian.Uint16(response[8:]))}
		client, err := net.DialUDP("udp4", nil, relay)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		client.SetDeadline(time.Now().Add(15 * time.Second))
		message := bytes.Repeat([]byte("game UDP payload"), 75)
		packet := append([]byte{0, 0, 0, 1, 10, 77, 0, 1, byte(18081 >> 8), byte(18081 & 255)}, message...)
		client.Write(packet)
		buffer := make([]byte, 2048)
		n, err := client.Read(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if n < 10 || string(buffer[10:n]) != string(message) {
			t.Fatalf("UDP payload mismatch: %v", buffer[:n])
		}
	})
}
