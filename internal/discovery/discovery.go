package discovery

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/grandcat/zeroconf"
)

// Service is the type every cache server advertises on the network bus.
const Service = "_easycache._tcp"

// Register announces the cache on the local network via mDNS/zeroconf. The
// returned server must be closed to un-announce. If mDNS is unavailable the
// error is returned so the caller can choose to keep serving without discovery.
func Register(instance string, port int, txt map[string]string) (*zeroconf.Server, error) {
	var kv []string
	for k, v := range txt {
		kv = append(kv, k+"="+v)
	}
	return zeroconf.Register(instance, Service, "local.", port, kv, nil)
}

// Server is a cache instance discovered on the network.
type Server struct {
	Instance string
	Host     net.IP
	Port     int
	Txt      []string
}

// URL returns the http endpoint for talking to this cache server.
func (s Server) URL() string {
	return "http://" + net.JoinHostPort(s.Host.String(), strconv.Itoa(s.Port))
}

// Lookup browses the network for cache servers and returns whatever answers
// arrive within timeout. An empty result (no error) means nothing was found.
func Lookup(ctx context.Context, timeout time.Duration) ([]Server, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	rz, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil, err
	}
	entries := make(chan *zeroconf.ServiceEntry, 20)
	if err := rz.Browse(ctx, Service, "local.", entries); err != nil {
		return nil, err
	}

	var out []Server
	for {
		select {
		case e, ok := <-entries:
			if !ok {
				return out, nil
			}
			out = append(out, convert(e))
		case <-ctx.Done():
			return out, nil
		}
	}
}

func convert(e *zeroconf.ServiceEntry) Server {
	ip := e.AddrIPv4
	if len(ip) == 0 {
		ip = e.AddrIPv6
	}
	return Server{
		Instance: e.Instance,
		Host:     firstValid(ip),
		Port:     e.Port,
		Txt:      e.Text,
	}
}

func firstValid(list []net.IP) net.IP {
	for _, ip := range list {
		if ip != nil {
			return ip
		}
	}
	return nil
}
