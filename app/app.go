package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"path"

	"github.com/bepass-org/warp-plus/iputils"
	"github.com/bepass-org/warp-plus/psiphon"
	"github.com/bepass-org/warp-plus/warp"
	"github.com/bepass-org/warp-plus/wireguard/tun"
	"github.com/bepass-org/warp-plus/wireguard/tun/netstack"
	"github.com/bepass-org/warp-plus/wiresocks"
)

const singleMTU = 1330
const doubleMTU = 1280 // minimum mtu for IPv6, may cause frag reassembly somewhere

type WarpOptions struct {
	Bind            netip.AddrPort
	Endpoint        string
	License         string
	DnsAddr         netip.Addr
	Psiphon         *PsiphonOptions
	Gool            bool
	Scan            *wiresocks.ScanOptions
	CacheDir        string
	Tun             bool
	FwMark          uint32
	WireguardConfig string
	Reserved        string
}

type PsiphonOptions struct {
	Country string
}

type WarpService struct {
	l             *slog.Logger
	opts          WarpOptions
	ctx           context.Context
	ctxCancelFunc context.CancelFunc
}

func NewWarpService(l *slog.Logger, opts WarpOptions) *WarpService {
	return &WarpService{l: l, opts: opts}
}

func (w *WarpService) ScanEndpoints(ctx context.Context) ([]string, error) {
	// make primary identity
	ident, err := warp.LoadOrCreateIdentity(w.l, path.Join(w.opts.CacheDir, "primary"), w.opts.License)
	if err != nil {
		w.l.Error("couldn't load primary warp identity")
		return nil, err
	}

	// Reading the private key from the 'Interface' section
	w.opts.Scan.PrivateKey = ident.PrivateKey

	// Reading the public key from the 'Peer' section
	w.opts.Scan.PublicKey = ident.Config.Peers[0].PublicKey

	res, err := wiresocks.RunScan(ctx, w.l, *w.opts.Scan)
	if err != nil {
		return nil, err
	}

	w.l.Debug("scan results", "endpoints", res)

	endpoints := make([]string, len(res))
	for i := 0; i < len(res); i++ {
		endpoints[i] = res[i].AddrPort.String()
	}

	return endpoints, nil
}

func (w *WarpService) StartPlainWireguard() error {
	if w.opts.WireguardConfig == "" {
		return errors.New("no wireguard config provided")
	}

	w.ctx, w.ctxCancelFunc = context.WithCancel(context.Background())
	if err := runWireguard(w.ctx, w.l, w.opts); err != nil {
		return err
	}

	return nil
}

func (w *WarpService) StartWarp() error {
	w.l.Info("running in normal warp mode")
	w.ctx, w.ctxCancelFunc = context.WithCancel(context.Background())

	endpoints := []string{w.opts.Endpoint, w.opts.Endpoint}
	if w.opts.Scan != nil {
		e, err := w.ScanEndpoints(w.ctx)
		if err != nil {
			return err
		}
		endpoints = e
	}
	w.l.Info("using warp endpoints", "endpoints", endpoints)

	// just run primary warp on bindAddress
	if err := runWarp(w.ctx, w.l, w.opts, endpoints[0]); err != nil {
		return err
	}

	return nil
}

func (w *WarpService) StartWarpOnWarp() error {
	w.l.Info("running in warp-on-warp (gool) mode")
	w.ctx, w.ctxCancelFunc = context.WithCancel(context.Background())

	endpoints := []string{w.opts.Endpoint, w.opts.Endpoint}
	if w.opts.Scan != nil {
		e, err := w.ScanEndpoints(w.ctx)
		if err != nil {
			return err
		}
		endpoints = e
	}
	w.l.Info("using warp endpoints", "endpoints", endpoints)

	// just run primary warp on bindAddress
	if err := runWarpOnWarp(w.ctx, w.l, w.opts, endpoints); err != nil {
		return err
	}

	return nil
}

func (w *WarpService) StartPsiphonOnWarp() error {
	w.l.Info("running in Psiphon (cfon) mode")
	w.ctx, w.ctxCancelFunc = context.WithCancel(context.Background())

	endpoints := []string{w.opts.Endpoint, w.opts.Endpoint}
	if w.opts.Scan != nil {
		e, err := w.ScanEndpoints(w.ctx)
		if err != nil {
			return err
		}
		endpoints = e
	}
	w.l.Info("using warp endpoints", "endpoints", endpoints)

	// just run primary warp on bindAddress
	if err := runWarpWithPsiphon(w.ctx, w.l, w.opts, endpoints[0]); err != nil {
		return err
	}

	return nil
}

func (w *WarpService) Stop() {
	if w.ctxCancelFunc != nil {
		w.ctxCancelFunc()
	}
}

func runWireguard(ctx context.Context, l *slog.Logger, opts WarpOptions) error {
	conf, err := wiresocks.ParseConfig(opts.WireguardConfig)
	if err != nil {
		return err
	}

	// Set up MTU
	conf.Interface.MTU = singleMTU
	// Set up DNS Address
	conf.Interface.DNS = []netip.Addr{opts.DnsAddr}

	// Enable trick and keepalive on all peers in config
	for i, peer := range conf.Peers {
		peer.Trick = true
		peer.KeepAlive = 5

		// Try resolving if the endpoint is a domain
		addr, err := iputils.ParseResolveAddressPort(peer.Endpoint, false, opts.DnsAddr.String())
		if err == nil {
			peer.Endpoint = addr.String()
		}

		conf.Peers[i] = peer
	}

	if opts.Tun {
		// Establish wireguard tunnel on tun interface
		var werr error
		var tunDev tun.Device
		for _, t := range []string{"t1", "t2"} {
			// Create a new tun interface
			tunDev, werr = newNormalTun([]netip.Addr{opts.DnsAddr})
			if werr != nil {
				continue
			}

			werr = establishWireguard(l, conf, tunDev, true, opts.FwMark, t)
			if werr != nil {
				continue
			}
			break
		}
		if werr != nil {
			return werr
		}

		l.Info("serving tun", "interface", "warp0")
		return nil
	}

	// Establish wireguard on userspace stack
	var werr error
	var tnet *netstack.Net
	var tunDev tun.Device
	for _, t := range []string{"t1", "t2"} {
		// Create userspace tun network stack
		tunDev, tnet, werr = netstack.CreateNetTUN(conf.Interface.Addresses, conf.Interface.DNS, conf.Interface.MTU)
		if werr != nil {
			continue
		}

		werr = establishWireguard(l, conf, tunDev, false, opts.FwMark, t)
		if werr != nil {
			continue
		}

		// Test wireguard connectivity
		werr = usermodeTunTest(ctx, l, tnet)
		if werr != nil {
			continue
		}
		break
	}
	if werr != nil {
		return werr
	}

	// Run a proxy on the userspace stack
	_, err = wiresocks.StartProxy(ctx, l, tnet, opts.Bind)
	if err != nil {
		return err
	}

	l.Info("serving proxy", "address", opts.Bind)

	return nil
}

func runWarp(ctx context.Context, l *slog.Logger, opts WarpOptions, endpoint string) error {
	// make primary identity
	ident, err := warp.LoadOrCreateIdentity(l, path.Join(opts.CacheDir, "primary"), opts.License)
	if err != nil {
		l.Error("couldn't load primary warp identity")
		return err
	}

	conf := generateWireguardConfig(ident)

	// Set up MTU
	conf.Interface.MTU = singleMTU
	// Set up DNS Address
	conf.Interface.DNS = []netip.Addr{opts.DnsAddr}

	// Enable trick and keepalive on all peers in config
	for i, peer := range conf.Peers {
		peer.Endpoint = endpoint
		peer.Trick = true
		peer.KeepAlive = 5

		if opts.Reserved != "" {
			r, err := wiresocks.ParseReserved(opts.Reserved)
			if err != nil {
				return err
			}
			peer.Reserved = r
		}

		conf.Peers[i] = peer
	}

	if opts.Tun {
		// Establish wireguard tunnel on tun interface
		var werr error
		var tunDev tun.Device
		for _, t := range []string{"t1", "t2"} {
			// Create a new tun interface
			tunDev, werr = newNormalTun([]netip.Addr{opts.DnsAddr})
			if werr != nil {
				continue
			}

			// Create userspace tun network stack
			werr = establishWireguard(l, &conf, tunDev, true, opts.FwMark, t)
			if werr != nil {
				continue
			}
			break
		}
		if werr != nil {
			return werr
		}
		l.Info("serving tun", "interface", "warp0")
		return nil
	}

	// Establish wireguard on userspace stack
	var werr error
	var tnet *netstack.Net
	var tunDev tun.Device
	for _, t := range []string{"t1", "t2"} {
		tunDev, tnet, werr = netstack.CreateNetTUN(conf.Interface.Addresses, conf.Interface.DNS, conf.Interface.MTU)
		if werr != nil {
			continue
		}

		werr = establishWireguard(l, &conf, tunDev, false, opts.FwMark, t)
		if werr != nil {
			continue
		}

		// Test wireguard connectivity
		werr = usermodeTunTest(ctx, l, tnet)
		if werr != nil {
			continue
		}
		break
	}
	if werr != nil {
		return werr
	}

	// Run a proxy on the userspace stack
	_, err = wiresocks.StartProxy(ctx, l, tnet, opts.Bind)
	if err != nil {
		return err
	}

	l.Info("serving proxy", "address", opts.Bind)
	return nil
}

func runWarpOnWarp(ctx context.Context, l *slog.Logger, opts WarpOptions, endpoints []string) error {
	// make primary identity
	ident1, err := warp.LoadOrCreateIdentity(l, path.Join(opts.CacheDir, "primary"), opts.License)
	if err != nil {
		l.Error("couldn't load primary warp identity")
		return err
	}

	conf := generateWireguardConfig(ident1)

	// Set up MTU
	conf.Interface.MTU = singleMTU
	// Set up DNS Address
	conf.Interface.DNS = []netip.Addr{opts.DnsAddr}

	// Enable trick and keepalive on all peers in config
	for i, peer := range conf.Peers {
		peer.Endpoint = endpoints[0]
		peer.Trick = true
		peer.KeepAlive = 5

		if opts.Reserved != "" {
			r, err := wiresocks.ParseReserved(opts.Reserved)
			if err != nil {
				return err
			}
			peer.Reserved = r
		}

		conf.Peers[i] = peer
	}

	// Establish wireguard on userspace stack and bind the wireguard sockets to the default interface and apply
	var werr error
	var tnet1 *netstack.Net
	var tunDev tun.Device
	for _, t := range []string{"t1", "t2"} {
		// Create userspace tun network stack
		tunDev, tnet1, werr = netstack.CreateNetTUN(conf.Interface.Addresses, conf.Interface.DNS, conf.Interface.MTU)
		if werr != nil {
			continue
		}

		werr = establishWireguard(l.With("gool", "outer"), &conf, tunDev, opts.Tun, opts.FwMark, t)
		if werr != nil {
			continue
		}

		// Test wireguard connectivity
		werr = usermodeTunTest(ctx, l, tnet1)
		if werr != nil {
			continue
		}
		break
	}
	if werr != nil {
		return werr
	}

	// Create a UDP port forward between localhost and the remote endpoint
	addr, err := wiresocks.NewVtunUDPForwarder(ctx, netip.MustParseAddrPort("127.0.0.1:0"), endpoints[0], tnet1, singleMTU)
	if err != nil {
		return err
	}

	// make secondary
	ident2, err := warp.LoadOrCreateIdentity(l, path.Join(opts.CacheDir, "secondary"), opts.License)
	if err != nil {
		l.Error("couldn't load secondary warp identity")
		return err
	}

	conf = generateWireguardConfig(ident2)

	// Set up MTU
	conf.Interface.MTU = doubleMTU
	// Set up DNS Address
	conf.Interface.DNS = []netip.Addr{opts.DnsAddr}

	// Enable keepalive on all peers in config
	for i, peer := range conf.Peers {
		peer.Endpoint = addr.String()
		peer.KeepAlive = 20

		if opts.Reserved != "" {
			r, err := wiresocks.ParseReserved(opts.Reserved)
			if err != nil {
				return err
			}
			peer.Reserved = r
		}

		conf.Peers[i] = peer
	}

	if opts.Tun {
		// Create a new tun interface
		tunDev, err := newNormalTun([]netip.Addr{opts.DnsAddr})
		if err != nil {
			return err
		}

		// Establish wireguard tunnel on tun interface but don't bind
		// wireguard sockets to default interface and don't apply fwmark.
		if err := establishWireguard(l.With("gool", "inner"), &conf, tunDev, false, opts.FwMark, "t0"); err != nil {
			return err
		}
		l.Info("serving tun", "interface", "warp0")
		return nil
	}

	// Create userspace tun network stack
	tunDev, tnet2, err := netstack.CreateNetTUN(conf.Interface.Addresses, conf.Interface.DNS, conf.Interface.MTU)
	if err != nil {
		return err
	}

	// Establish wireguard on userspace stack
	if err := establishWireguard(l.With("gool", "inner"), &conf, tunDev, false, opts.FwMark, "t0"); err != nil {
		return err
	}

	// Test wireguard connectivity
	if err := usermodeTunTest(ctx, l, tnet2); err != nil {
		return err
	}

	_, err = wiresocks.StartProxy(ctx, l, tnet2, opts.Bind)
	if err != nil {
		return err
	}

	l.Info("serving proxy", "address", opts.Bind)
	return nil
}

func runWarpWithPsiphon(ctx context.Context, l *slog.Logger, opts WarpOptions, endpoint string) error {
	// make primary identity
	ident, err := warp.LoadOrCreateIdentity(l, path.Join(opts.CacheDir, "primary"), opts.License)
	if err != nil {
		l.Error("couldn't load primary warp identity")
		return err
	}

	conf := generateWireguardConfig(ident)

	// Set up MTU
	conf.Interface.MTU = singleMTU
	// Set up DNS Address
	conf.Interface.DNS = []netip.Addr{opts.DnsAddr}

	// Enable trick and keepalive on all peers in config
	for i, peer := range conf.Peers {
		peer.Endpoint = endpoint
		peer.Trick = true
		peer.KeepAlive = 5

		if opts.Reserved != "" {
			r, err := wiresocks.ParseReserved(opts.Reserved)
			if err != nil {
				return err
			}
			peer.Reserved = r
		}

		conf.Peers[i] = peer
	}

	// Establish wireguard on userspace stack
	var werr error
	var tnet *netstack.Net
	var tunDev tun.Device
	for _, t := range []string{"t1", "t2"} {
		// Create userspace tun network stack
		tunDev, tnet, werr = netstack.CreateNetTUN(conf.Interface.Addresses, conf.Interface.DNS, conf.Interface.MTU)
		if werr != nil {
			continue
		}

		werr = establishWireguard(l, &conf, tunDev, false, opts.FwMark, t)
		if werr != nil {
			continue
		}

		// Test wireguard connectivity
		werr = usermodeTunTest(ctx, l, tnet)
		if werr != nil {
			continue
		}
		break
	}
	if werr != nil {
		return werr
	}

	// Run a proxy on the userspace stack
	warpBind, err := wiresocks.StartProxy(ctx, l, tnet, netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		return err
	}

	// run psiphon
	err = psiphon.RunPsiphon(ctx, l.With("subsystem", "psiphon"), warpBind, opts.CacheDir, opts.Bind, opts.Psiphon.Country)
	if err != nil {
		return fmt.Errorf("unable to run psiphon %w", err)
	}

	l.Info("serving proxy", "address", opts.Bind)
	return nil
}

func generateWireguardConfig(i *warp.Identity) wiresocks.Configuration {
	priv, _ := wiresocks.EncodeBase64ToHex(i.PrivateKey)
	pub, _ := wiresocks.EncodeBase64ToHex(i.Config.Peers[0].PublicKey)
	clientID, _ := base64.StdEncoding.DecodeString(i.Config.ClientID)
	return wiresocks.Configuration{
		Interface: &wiresocks.InterfaceConfig{
			PrivateKey: priv,
			Addresses: []netip.Addr{
				netip.MustParseAddr(i.Config.Interface.Addresses.V4),
				netip.MustParseAddr(i.Config.Interface.Addresses.V6),
			},
		},
		Peers: []wiresocks.PeerConfig{{
			PublicKey:    pub,
			PreSharedKey: "0000000000000000000000000000000000000000000000000000000000000000",
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
			},
			Endpoint: i.Config.Peers[0].Endpoint.Host,
			Reserved: [3]byte{clientID[0], clientID[1], clientID[2]},
		}},
	}
}
