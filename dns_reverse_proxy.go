/*
Binary dns_reverse_proxy is a DNS reverse proxy to route queries to DNS servers.

To illustrate, imagine an HTTP reverse proxy but for DNS.
It listens on both TCP/UDP IPv4/IPv6 on specified port.
Since the upstream servers will not see the real client IPs but the proxy,
you can specify a list of IPs allowed to transfer (AXFR/IXFR).

Example usage:
        $ go run dns_reverse_proxy.go -address :53 \
                -default 8.8.8.8:53 \
                -route .example.com.=8.8.4.4:53 \
                -route .example2.com.=8.8.4.4:53,1.1.1.1:53 \
				-allow-transfer 1.2.3.4,::1 \
				-typeroute CAA=127.0.0.1:4553

A query for example.net or example.com will go to 8.8.8.8:53, the default.
However, a query for subdomain.example.com will go to 8.8.4.4:53. -default
is optional - if it is not given then the server will return a failure for
queries for domains where a route has not been given.
*/
package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type flagStringList []string

func (i *flagStringList) String() string {
	return fmt.Sprint(*i)
}

func (i *flagStringList) Set(value string) error {
	*i = append(*i, value)
	return nil
}


var (
	address = flag.String("address", ":53", "Address to listen to (TCP and UDP)")

	defaultServer = flag.String("default", "",
		"Default DNS server where to send queries if no route matched (host:port)")

	routeLists flagStringList
	routes     map[string][]string

	typeRouteLists flagStringList
	typeRoutes     map[string][]string

	allowTransfer = flag.String("allow-transfer", "",
		"List of IPs allowed to transfer (AXFR/IXFR)")
	transferIPs []string


	dns_types = map[string]uint16{
		"LOC": 29,
		"NXT": 30,
		"CDNSKEY": 60,
		"UINFO": 100,
		"AAAA": 28,
		"EUI64": 109,
		"L64": 106,
		"CNAME": 5,
		"MINFO": 14,
		"EID": 31,
		"GPOS": 27,
		"X25": 19,
		"HINFO": 13,
		"CAA": 257,
		"NULL": 10,
		"DNSKEY": 48,
		"DS": 43,
		"ISDN": 20,
		"AVC": 258,
		"SOA": 6,
		"RP": 17,
		"UID": 101,
		"CSYNC": 62,
		"PX": 26,
		"DLV": 32769,
		"NSEC3": 50,
		"DNAME": 39,
		"MAILA": 254,
		"EUI48": 108,
		"LP": 107,
		"AFSDB": 18,
		"SSHFP": 44,
		"TXT": 16,
		"PTR": 12,
		"SPF": 99,
		"TA": 32768,
		"A": 1,
		"RT": 21,
		"None": 0,
		"TSIG": 250,
		"NIMLOC": 32,
		"RKEY": 57,
		"TLSA": 52,
		"NAPTR": 35,
		"HIP": 55,
		"NSEC": 47,
		"URI": 256,
		"GID": 102,
		"SRV": 33,
		"ANY": 255,
		"CDS": 59,
		"NSEC3PARAM": 51,
		"UNSPEC": 103,
		"NSAPPTR": 23,
		"ATMA": 34,
		"RRSIG": 46,
		"OPENPGPKEY": 61,
		"MD": 3,
		"MG": 8,
		"MF": 4,
		"Reserved": 65535,
		"IXFR": 251,
		"MB": 7,
		"NS": 2,
		"DHCID": 49,
		"NID": 104,
		"TKEY": 249,
		"MAILB": 253,
		"CERT": 37,
		"NINFO": 56,
		"L32": 105,
		"KEY": 25,
		"MR": 9,
		"SIG": 24,
		"KX": 36,
		"AXFR": 252,
		"MX": 15,
		"SMIMEA": 53,
		"TALINK": 58,
	}
	
)

func init() {
	rand.Seed(time.Now().Unix())
	flag.Var(&routeLists, "route", "List of routes where to send queries (domain=host:port,[host:port,...])")
	flag.Var(&typeRouteLists, "typeroute", "List of types to route independantly (type=host:port,[host:port,...])")
}

func main() {
	flag.Parse()

	transferIPs = strings.Split(*allowTransfer, ",")
	routes = make(map[string][]string)
	for _, routeList := range routeLists {
		s := strings.SplitN(routeList, "=", 2)
		if len(s) != 2 || len(s[0]) == 0 || len(s[1]) == 0 {
			log.Fatal("invalid -route, must be domain=host:port,[host:port,...]")
		}
		var backends []string
		for _, backend := range strings.Split(s[1], ",") {
			if !validHostPort(backend) {
				log.Fatalf("invalid host:port for %v", backend)
			}
			backends = append(backends, backend)
		}
		if !strings.HasSuffix(s[0], ".") {
			s[0] += "."
		}
		routes[strings.ToLower(s[0])] = backends
	}

	typeRoutes = make(map[string][]string)
	for _, typeRouteList := range typeRouteLists {
		s := strings.SplitN(typeRouteList, "=", 2)
		if len(s) != 2 || len(s[0]) == 0 || len(s[1]) == 0 {
			log.Fatal("invalid -typeroute, must be domain=host:port,[host:port,...]")
		}
		var backends []string
		for _, backend := range strings.Split(s[1], ",") {
			if !validHostPort(backend) {
				log.Fatalf("invalid host:port for %v", backend)
			}
			backends = append(backends, backend)
		}
		if !validRequestType(strings.ToUpper(s[0])) {
			log.Fatalf("invalid DNS query type %v", s[0])
		}
		typeRoutes[strings.ToUpper(s[0])] = backends
	}

	udpServer := &dns.Server{Addr: *address, Net: "udp"}
	tcpServer := &dns.Server{Addr: *address, Net: "tcp"}
	dns.HandleFunc(".", route)
	go func() {
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	// Wait for SIGINT or SIGTERM
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	udpServer.Shutdown()
	tcpServer.Shutdown()
}

func validHostPort(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || port == "" {
		return false
	}
	return true
}

func validRequestType(s string) bool {
	if _, ok := dns_types[s]; ok {
		return true
	}
	return false
}


func route(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 || !allowed(w, req) {
		dns.HandleFailed(w, req)
		return
	}
	
	lcType := req.Question[0].Qtype
	for typer, addrs := range typeRoutes {
		if lcType == dns_types[typer] {
			addr := addrs[0]
			if n := len(addrs); n > 1 {
				addr = addrs[rand.Intn(n)]
			}
			proxy(addr, w, req)
			return
		}
	}

	lcName := strings.ToLower(req.Question[0].Name)
	for name, addrs := range routes {
		if strings.HasSuffix(lcName, name) {
			addr := addrs[0]
			if n := len(addrs); n > 1 {
				addr = addrs[rand.Intn(n)]
			}
			proxy(addr, w, req)
			return
		}
	}

	if *defaultServer == "" {
		dns.HandleFailed(w, req)
		return
	}

	proxy(*defaultServer, w, req)
}

func isTransfer(req *dns.Msg) bool {
	for _, q := range req.Question {
		switch q.Qtype {
		case dns.TypeIXFR, dns.TypeAXFR:
			return true
		}
	}
	return false
}


func allowed(w dns.ResponseWriter, req *dns.Msg) bool {
	if !isTransfer(req) {
		return true
	}
	remote, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	for _, ip := range transferIPs {
		if ip == remote {
			return true
		}
	}
	return false
}

func proxy(addr string, w dns.ResponseWriter, req *dns.Msg) {
	transport := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		transport = "tcp"
	}
	if isTransfer(req) {
		if transport != "tcp" {
			dns.HandleFailed(w, req)
			return
		}
		t := new(dns.Transfer)
		c, err := t.In(req, addr)
		if err != nil {
			dns.HandleFailed(w, req)
			return
		}
		if err = t.Out(w, req, c); err != nil {
			dns.HandleFailed(w, req)
			return
		}
		return
	}
	
	c := &dns.Client{Net: transport}
	resp, _, err := c.Exchange(req, addr)
	if err != nil {
		dns.HandleFailed(w, req)
		return
	}
	w.WriteMsg(resp)
}
