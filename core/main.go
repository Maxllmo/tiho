// Tiho's loopback SOCKS gateway. The VPN data plane is the official AmneziaWG engine.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

type launchConfig struct {
	Config string `json:"config"`
	Listen string `json:"listen"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("Tiho AWG gateway 2.0.0 / AmneziaWG v3.1.20260828")
		return
	}
	log.SetFlags(0)
	var cfg launchConfig
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 1024*1024)).Decode(&cfg); err != nil {
		log.Fatal("Invalid gateway configuration")
	}
	if err := run(cfg); err != nil {
		log.Fatal(err)
	}
}

func run(cfg launchConfig) error {
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil || host != "127.0.0.1" {
		return errors.New("SOCKS listener must use IPv4 loopback")
	}
	parsed, err := parseConfig(cfg.Config)
	if err != nil {
		return err
	}
	tun, network, err := netstack.CreateNetTUN(parsed.addresses, parsed.dns, parsed.mtu)
	if err != nil {
		return fmt.Errorf("create network stack: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "AWG: "))
	defer dev.Close()
	if err := dev.IpcSet(parsed.uapi); err != nil {
		return errors.New("AmneziaWG rejected the configuration; check keys and protocol parameters")
	}
	if err := dev.Up(); err != nil {
		return fmt.Errorf("start AmneziaWG: %w", err)
	}
	listener, err := net.Listen("tcp4", cfg.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	go func() { <-ctx.Done(); listener.Close() }()
	log.Println("READY " + listener.Addr().String())
	return serve(ctx, listener, network)
}

type parsedConfig struct {
	addresses []netip.Addr
	dns       []netip.Addr
	mtu       int
	uapi      string
}

var customKeys = map[string]string{
	"jc": "jc", "jmin": "jmin", "jmax": "jmax", "s1": "s1", "s2": "s2", "s3": "s3", "s4": "s4",
	"h1": "h1", "h2": "h2", "h3": "h3", "h4": "h4", "i1": "i1", "i2": "i2", "i3": "i3", "i4": "i4", "i5": "i5",
	"headerprotectionkey": "header_protection_key", "contentpaddingaddition": "content_padding_addition",
	"rekeyaftertime": "rekey_after_time", "rekeytimeout": "rekey_timeout", "rejectaftertime": "reject_after_time",
	"keepalivetimeout": "keepalive_timeout", "maxhandshakeattempts": "max_handshake_attempts",
	"randomtrailers": "random_trailers", "disablecookies": "disable_cookies",
}

func parseConfig(text string) (parsedConfig, error) {
	p := parsedConfig{mtu: 1280}
	iface, peer := map[string]string{}, map[string]string{}
	section := ""
	peers := 0
	scanner := bufio.NewScanner(strings.NewReader(strings.TrimPrefix(text, "\ufeff")))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(line)
			if section == "[peer]" {
				peers++
			}
			if section != "[peer]" && section != "[interface]" {
				return p, errors.New("Unknown configuration section")
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return p, errors.New("Invalid configuration line")
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if section == "[interface]" {
			iface[key] = value
		} else if section == "[peer]" {
			peer[key] = value
		} else {
			return p, errors.New("Missing configuration section")
		}
	}
	if err := scanner.Err(); err != nil {
		return p, err
	}
	if peers != 1 {
		return p, errors.New("Import a client configuration with exactly one [Peer]")
	}
	for _, s := range strings.Split(iface["address"], ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return p, errors.New("Invalid or missing client Address")
		}
		p.addresses = append(p.addresses, prefix.Addr())
	}
	if s := iface["dns"]; s != "" {
		for _, v := range strings.Split(s, ",") {
			if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
				p.dns = append(p.dns, a)
			}
		}
	}
	if len(p.dns) == 0 {
		p.dns = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	if v := iface["mtu"]; v != "" {
		m, err := strconv.Atoi(v)
		if err != nil || m < 576 || m > 9000 {
			return p, errors.New("Invalid MTU")
		}
		p.mtu = m
	}
	private, err := hexKey(iface["privatekey"])
	if err != nil {
		return p, errors.New("Invalid client PrivateKey")
	}
	public, err := hexKey(peer["publickey"])
	if err != nil {
		return p, errors.New("Invalid server PublicKey")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nlisten_port=0\n", private)
	for name, value := range iface {
		if api, ok := customKeys[name]; ok {
			if strings.ContainsAny(value, "\r\n\x00") {
				return p, errors.New("Invalid protocol parameter")
			}
			if name == "headerprotectionkey" {
				value, err = hexKey(value)
				if err != nil {
					return p, errors.New("Invalid HeaderProtectionKey")
				}
			}
			fmt.Fprintf(&b, "%s=%s\n", api, value)
		}
	}
	endpoint, err := net.ResolveUDPAddr("udp", peer["endpoint"])
	if err != nil || endpoint.Port == 0 || endpoint.IP == nil {
		return p, errors.New("Invalid or unreachable peer Endpoint")
	}
	fmt.Fprintf(&b, "replace_peers=true\npublic_key=%s\nendpoint=%s\n", public, endpoint.String())
	if value := peer["presharedkey"]; value != "" {
		key, err := hexKey(value)
		if err != nil {
			return p, errors.New("Invalid PresharedKey")
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", key)
	}
	keepalive := peer["persistentkeepalive"]
	if keepalive == "" {
		keepalive = "25"
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=%s\nreplace_allowed_ips=true\n", keepalive)
	// Tiho owns split routing. The single VPN peer carries all non-excluded destinations.
	b.WriteString("allowed_ip=0.0.0.0/0\nallowed_ip=::/0\n")
	p.uapi = b.String()
	return p, nil
}

func hexKey(s string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(key) != 32 {
		return "", errors.New("expected a base64-encoded 32-byte key")
	}
	return hex.EncodeToString(key), nil
}

// The concrete netstack.Net is retained for UDP, avoiding any host-network fallback.
func serve(ctx context.Context, listener net.Listener, network *netstack.Net) error {
	slots := make(chan struct{}, 512)
	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); defer client.Close(); handleSOCKS(ctx, client, network) }()
		default:
			client.Close()
		}
	}
}

func handleSOCKS(ctx context.Context, client net.Conn, network *netstack.Net) {
	client.SetDeadline(time.Now().Add(15 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(client, h[:]); err != nil || h[0] != 5 {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	noAuth := false
	for _, m := range methods {
		if m == 0 {
			noAuth = true
		}
	}
	if !noAuth {
		client.Write([]byte{5, 255})
		return
	}
	if _, err := client.Write([]byte{5, 0}); err != nil {
		return
	}
	var req [4]byte
	if _, err := io.ReadFull(client, req[:]); err != nil || req[0] != 5 || req[2] != 0 {
		return
	}
	target, err := readAddress(client, req[3])
	if err != nil {
		return
	}
	switch req[1] {
	case 1:
		dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		upstream, err := network.DialContext(dialCtx, "tcp", target)
		cancel()
		if err != nil {
			reply(client, 5, nil)
			return
		}
		defer upstream.Close()
		if err := reply(client, 0, nil); err != nil {
			return
		}
		client.SetDeadline(time.Time{})
		done := make(chan struct{})
		go func() {
			io.Copy(upstream, client)
			if half, ok := upstream.(interface{ CloseWrite() error }); ok {
				half.CloseWrite()
			} else {
				upstream.Close()
			}
			close(done)
		}()
		io.Copy(client, upstream)
		client.Close()
		<-done
	case 3:
		associateUDP(ctx, client, network)
	default:
		reply(client, 7, nil)
	}
}

func readAddress(r io.Reader, atyp byte) (string, error) {
	var host string
	switch atyp {
	case 1:
		b := make([]byte, 4)
		if _, e := io.ReadFull(r, b); e != nil {
			return "", e
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, e := io.ReadFull(r, b); e != nil {
			return "", e
		}
		host = net.IP(b).String()
	case 3:
		var size [1]byte
		if _, e := io.ReadFull(r, size[:]); e != nil {
			return "", e
		}
		if size[0] == 0 {
			return "", errors.New("empty domain")
		}
		b := make([]byte, size[0])
		if _, e := io.ReadFull(r, b); e != nil {
			return "", e
		}
		host = string(b)
	default:
		return "", errors.New("invalid address type")
	}
	var p [2]byte
	if _, e := io.ReadFull(r, p[:]); e != nil {
		return "", e
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
}

func reply(w io.Writer, status byte, addr *net.UDPAddr) error {
	b := []byte{5, status, 0, 1, 127, 0, 0, 1, 0, 0}
	if addr != nil {
		binary.BigEndian.PutUint16(b[8:], uint16(addr.Port))
	}
	_, err := w.Write(b)
	return err
}

func associateUDP(ctx context.Context, control net.Conn, network *netstack.Net) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		reply(control, 1, nil)
		return
	}
	defer udp.Close()
	if err := reply(control, 0, udp.LocalAddr().(*net.UDPAddr)); err != nil {
		return
	}
	control.SetDeadline(time.Time{})
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { var b [1]byte; control.Read(b[:]); cancel(); udp.Close() }()
	var mu sync.Mutex
	flows := map[string]net.Conn{}
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range flows {
			c.Close()
		}
	}()
	var source *net.UDPAddr
	buf := make([]byte, 65535)
	for {
		n, from, err := udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !from.IP.IsLoopback() || n < 7 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
			continue
		}
		if source == nil {
			source = from
		} else if source.String() != from.String() {
			continue
		}
		reader := strings.NewReader(string(buf[4:n]))
		target, err := readAddress(reader, buf[3])
		if err != nil {
			continue
		}
		payload := append([]byte(nil), buf[n-reader.Len():n]...)
		mu.Lock()
		remote := flows[target]
		flowCount := len(flows)
		mu.Unlock()
		if remote == nil {
			if flowCount >= 256 {
				continue
			}
			host, portText, err := net.SplitHostPort(target)
			if err != nil {
				continue
			}
			port, _ := strconv.Atoi(portText)
			resolveCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			addresses, err := network.LookupContextHost(resolveCtx, host)
			stop()
			if err != nil || len(addresses) == 0 {
				continue
			}
			conn, err := network.DialUDP(nil, &net.UDPAddr{IP: net.ParseIP(addresses[0]), Port: port})
			if err != nil {
				continue
			}
			remote = conn
			mu.Lock()
			flows[target] = remote
			mu.Unlock()
			go func(target string, c net.Conn, destination *net.UDPAddr) {
				defer c.Close()
				defer func() { mu.Lock(); delete(flows, target); mu.Unlock() }()
				response := make([]byte, 65535)
				for {
					c.SetReadDeadline(time.Now().Add(2 * time.Minute))
					n, err := c.Read(response)
					if err != nil {
						return
					}
					packet, err := udpPacket(c.RemoteAddr(), response[:n])
					if err != nil {
						return
					}
					if _, err = udp.WriteToUDP(packet, destination); err != nil {
						return
					}
				}
			}(target, remote, source)
		}
		remote.SetWriteDeadline(time.Now().Add(5 * time.Second))
		remote.Write(payload)
	}
}

func udpPacket(addr net.Addr, payload []byte) ([]byte, error) {
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("invalid UDP reply address")
	}
	packet := []byte{0, 0, 0, 1}
	if v4 := ip.To4(); v4 != nil {
		packet = append(packet, v4...)
	} else {
		packet[3] = 4
		packet = append(packet, ip.To16()...)
	}
	port, _ := strconv.Atoi(portText)
	packet = append(packet, byte(port>>8), byte(port))
	return append(packet, payload...), nil
}
