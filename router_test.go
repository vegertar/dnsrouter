// Copyright 2013 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// at https://github.com/julienschmidt/httprouter/blob/master.LICENSE
//
// Copyright {yyyy} {name of copyright owner}
// Use of this source code is governed by a Apache license that can be found
// at https://github.com/coredns/coredns/blob/master/LICENSE

package dnsrouter

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestParams(t *testing.T) {
	ps := Params{
		Param{"param1", "value1"},
		Param{"param2", "value2"},
		Param{"param3", "value3"},
	}
	for i := range ps {
		if val := ps.ByName(ps[i].Key); val != ps[i].Value {
			t.Errorf("Wrong value for %s: Got %s; Want %s", ps[i].Key, val, ps[i].Value)
		}
	}
	if val := ps.ByName("noKey"); val != "" {
		t.Errorf("Expected empty string for not found key; got: %s", val)
	}
}
func TestRouter(t *testing.T) {
	router := New()

	routed := false
	router.HandleFunc(":name.org", func(w ResponseWriter, r *Request) {
		routed = true
		want := "example"
		if v := r.Param("name"); v != want {
			t.Fatalf("wrong wildcard values: want %v, got %v", want, v)
		}
	})

	w := new(responseWriter)
	router.ServeDNS(w, NewRequest("example.org", dns.TypeA))

	if !routed {
		t.Fatal("routing failed")
	}
}

func TestRouterChaining(t *testing.T) {
	router1 := New()
	router2 := New()
	router1.NameError = router2

	fooHit := false
	router1.HandleFunc("foo", func(w ResponseWriter, req *Request) {
		fooHit = true
	})

	barHit := false
	router2.HandleFunc("bar", func(w ResponseWriter, req *Request) {
		barHit = true
	})

	w := &responseWriter{}
	router1.ServeDNS(w, NewRequest("foo", dns.TypeA))
	if !(w.msg.Rcode == dns.RcodeSuccess && fooHit) {
		t.Errorf("Regular routing failed with router chaining.")
		t.FailNow()
	}

	w = &responseWriter{}
	router1.ServeDNS(w, NewRequest("bar", dns.TypeA))
	if !(w.msg.Rcode == dns.RcodeSuccess && barHit) {
		t.Errorf("Chained routing failed with router chaining.")
		t.FailNow()
	}

	w = &responseWriter{}
	router1.ServeDNS(w, NewRequest("qax", dns.TypeA))
	if !(w.msg.Rcode == dns.RcodeNameError) {
		t.Errorf("NameError behavior failed with router chaining.")
		t.FailNow()
	}
}

func TestRouterPanicHandler(t *testing.T) {
	router := New()
	panicHandled := false

	router.PanicHandler = func(rw ResponseWriter, r *Request, p interface{}) {
		panicHandled = true
	}

	router.HandleFunc(":name.user", func(_ ResponseWriter, _ *Request) {
		panic("oops!")
	})

	w := &responseWriter{}
	req := NewRequest("gopher.user", dns.TypeA)

	defer func() {
		if rcv := recover(); rcv != nil {
			t.Fatal("handling panic failed")
		}
	}()

	router.ServeDNS(w, req)

	if !panicHandled {
		t.Fatal("simulating failed")
	}
}

func TestRouterHandle(t *testing.T) {
	router := New()
	router.Handle("", NoErrorHandler)
	recv := catchPanic(func() {
		router.Handle("", nil)
	})
	if !strings.Contains(fmt.Sprint(recv), "missing Handler") {
		t.Fatal("got error:", recv)
	}

	router.Handle("example.org", NoErrorHandler)

	recv = catchPanic(func() {
		router.Handle(" example.org ", nil)
	})
	if !strings.Contains(fmt.Sprint(recv), "not a TTL") {
		t.Fatal("got error:", recv)
	}

	router.Handle("example.org A", NoErrorHandler)
	router.Handle("example.org IN A", NoErrorHandler)

	recv = catchPanic(func() {
		router.Handle("example.org IN", NoErrorHandler)
	})
	if !strings.Contains(fmt.Sprint(recv), "not a TTL") {
		t.Fatal("got error:", recv)
	}

	router.Handle(":x.example.org", NoErrorHandler)
	router.Handle(":x.example.org", NoErrorHandler)
	router.Handle("x.:x.example.org", NoErrorHandler)

	recv = catchPanic(func() {
		router.Handle(":y.example.org", NoErrorHandler)
	})
	if !strings.Contains(fmt.Sprint(recv), "existing wildcard ':x'") {
		t.Fatal("got error:", recv)
	}

	router.Handle(":x.example.org A", NoErrorHandler)
	router.Handle(":x.example.org A", NoErrorHandler)
	router.Handle("x.:x.example.org A", NoErrorHandler)
}

func TestRouterLookup(t *testing.T) {
	routed := false
	wantHandle := func(_ ResponseWriter, _ *Request) {
		routed = true
	}
	wantParams := Params{Param{"name", "gopher"}}

	router := New()

	// try empty router first
	handles, _ := router.Lookup("nope", dns.ClassINET)
	if handles != nil {
		t.Fatalf("Got handles for unregistered pattern: %v", handles)
	}

	// insert route and try again
	router.HandleFunc(":name.user", wantHandle)

	handlers, params := router.Lookup("gopher.user", dns.ClassINET)
	if handlers == nil {
		t.Fatal("Got no handlers!")
	} else {
		for _, h := range handlers {
			h.Handler.ServeDNS(nil, nil)
		}
		if !routed {
			t.Fatal("Routing failed!")
		}
	}

	if !reflect.DeepEqual(params, wantParams) {
		t.Fatalf("Wrong parameter values: want %v, got %v", wantParams, params)
	}

	handlers, _ = router.Lookup(".gopher.user", dns.ClassINET)
	if handlers != nil {
		t.Fatalf("Got handlers for unregistered pattern: %v", handlers)
	}

	handlers, _ = router.Lookup("nope", dns.ClassINET)
	if handlers != nil {
		t.Fatalf("Got handlers for unregistered pattern: %v", handlers)
	}
}

func TestCNAME(t *testing.T) {
	const s = `
$TTL    30M
$ORIGIN example.org.
@       IN      SOA     linode.atoom.net. miek.miek.nl. (
                             1282630057 ; Serial
                             4H         ; Refresh
                             1H         ; Retry
                             7D         ; Expire
                             4H )       ; Negative Cache TTL
a               IN      A       127.0.0.1
www3            IN      CNAME   www2
www2            IN      CNAME   www1
www1            IN      CNAME   www
www             IN      CNAME   a
dangling        IN      CNAME   foo
external        IN      CNAME   www.example.net.`

	var cnameTestCases = []testCase{
		{
			Qname: "a.example.org.", Qtype: dns.TypeA,
			Answer: []dns.RR{
				a("a.example.org. 1800	IN	A 127.0.0.1"),
			},
		},
		{
			Qname: "www3.example.org.", Qtype: dns.TypeCNAME,
			Answer: []dns.RR{
				cname("www3.example.org. 1800	IN	CNAME www2.example.org."),
			},
		},
		{
			Qname: "dangling.example.org.", Qtype: dns.TypeA,
			Answer: []dns.RR{
				cname("dangling.example.org. 1800	IN	CNAME foo.example.org."),
			},
			Ns: []dns.RR{
				soa("example.org.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"),
			},
			Rcode: dns.RcodeNameError,
		},
		{
			Qname: "www3.example.org.", Qtype: dns.TypeA,
			Answer: []dns.RR{
				a("a.example.org. 1800	IN	A 127.0.0.1"),
				cname("www.example.org. 1800	IN	CNAME a.example.org."),
				cname("www1.example.org. 1800	IN	CNAME www.example.org."),
				cname("www2.example.org. 1800	IN	CNAME www1.example.org."),
				cname("www3.example.org. 1800	IN	CNAME www2.example.org."),
			},
		},
	}

	router := New()
	router.HandleZone(strings.NewReader(s), "example.org", "stdin")

	for _, tc := range cnameTestCases {
		resp := new(responseWriter)
		router.ServeDNS(resp, &Request{Msg: tc.Msg()})
		sortAndCheck(t, &resp.msg, tc)
	}
}

func TestLookup(t *testing.T) {
	const s = `
$TTL    30M
$ORIGIN miek.nl.
@       IN      SOA     linode.atoom.net. miek.miek.nl. (
                             1282630057 ; Serial
                             4H         ; Refresh
                             1H         ; Retry
                             7D         ; Expire
                             4H )       ; Negative Cache TTL
                IN      NS      linode.atoom.net.
                IN      NS      ns-ext.nlnetlabs.nl.
                IN      NS      omval.tednet.nl.
                IN      NS      ext.ns.whyscream.net.
                IN      MX      1  aspmx.l.google.com.
                IN      MX      5  alt1.aspmx.l.google.com.
                IN      MX      5  alt2.aspmx.l.google.com.
                IN      MX      10 aspmx2.googlemail.com.
                IN      MX      10 aspmx3.googlemail.com.
		IN      A       139.162.196.78
		IN      AAAA    2a01:7e00::f03c:91ff:fef1:6735
a               IN      A       139.162.196.78
                IN      AAAA    2a01:7e00::f03c:91ff:fef1:6735
www             IN      CNAME   a
archive         IN      CNAME   a
srv		IN	SRV     10 10 8080 a.miek.nl.
mx		IN	MX      10 a.miek.nl.`

	var miekAuth = []dns.RR{
		ns("miek.nl.	1800	IN	NS	ext.ns.whyscream.net."),
		ns("miek.nl.	1800	IN	NS	linode.atoom.net."),
		ns("miek.nl.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
		ns("miek.nl.	1800	IN	NS	omval.tednet.nl."),
	}

	var dnsTestCases = []testCase{
		{
			Qname: "www.miek.nl.", Qtype: dns.TypeA,
			Answer: []dns.RR{
				a("a.miek.nl.	1800	IN	A	139.162.196.78"),
				cname("www.miek.nl.	1800	IN	CNAME	a.miek.nl."),
			},
			Ns: miekAuth,
		},
		{
			Qname: "www.miek.nl.", Qtype: dns.TypeAAAA,
			Answer: []dns.RR{
				aaaa("a.miek.nl.	1800	IN	AAAA	2a01:7e00::f03c:91ff:fef1:6735"),
				cname("www.miek.nl.	1800	IN	CNAME	a.miek.nl."),
			},
			Ns: miekAuth,
		},
		{
			Qname: "miek.nl.", Qtype: dns.TypeSOA,
			Answer: []dns.RR{
				soa("miek.nl.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"),
			},
			Ns: miekAuth,
		},
		{
			Qname: "miek.nl.", Qtype: dns.TypeAAAA,
			Answer: []dns.RR{
				aaaa("miek.nl.	1800	IN	AAAA	2a01:7e00::f03c:91ff:fef1:6735"),
			},
			Ns: miekAuth,
		},
		{
			Qname: "mIeK.NL.", Qtype: dns.TypeAAAA,
			Answer: []dns.RR{
				aaaa("miek.nl.	1800	IN	AAAA	2a01:7e00::f03c:91ff:fef1:6735"),
			},
			Ns: miekAuth,
		},
		{
			Qname: "miek.nl.", Qtype: dns.TypeMX,
			Answer: []dns.RR{
				mx("miek.nl.	1800	IN	MX	1 aspmx.l.google.com."),
				mx("miek.nl.	1800	IN	MX	10 aspmx2.googlemail.com."),
				mx("miek.nl.	1800	IN	MX	10 aspmx3.googlemail.com."),
				mx("miek.nl.	1800	IN	MX	5 alt1.aspmx.l.google.com."),
				mx("miek.nl.	1800	IN	MX	5 alt2.aspmx.l.google.com."),
			},
			Ns: miekAuth,
		},
		{
			Qname: "a.miek.nl.", Qtype: dns.TypeSRV,
			Ns: []dns.RR{
				soa("miek.nl.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"),
			},
		},
		{
			Qname: "b.miek.nl.", Qtype: dns.TypeA,
			Rcode: dns.RcodeNameError,
			Ns: []dns.RR{
				soa("miek.nl.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"),
			},
		},
		{
			Qname: "srv.miek.nl.", Qtype: dns.TypeSRV,
			Answer: []dns.RR{
				srv("srv.miek.nl.	1800	IN	SRV	10 10 8080  a.miek.nl."),
			},
			Extra: []dns.RR{
				a("a.miek.nl.	1800	IN	A       139.162.196.78"),
				aaaa("a.miek.nl.	1800	IN	AAAA	2a01:7e00::f03c:91ff:fef1:6735"),
			},
			Ns: miekAuth,
		},
		{
			Qname: "mx.miek.nl.", Qtype: dns.TypeMX,
			Answer: []dns.RR{
				mx("mx.miek.nl.	1800	IN	MX	10 a.miek.nl."),
			},
			Extra: []dns.RR{
				a("a.miek.nl.	1800	IN	A       139.162.196.78"),
				aaaa("a.miek.nl.	1800	IN	AAAA	2a01:7e00::f03c:91ff:fef1:6735"),
			},
			Ns: miekAuth,
		},
	}

	router := New()
	router.HandleZone(strings.NewReader(s), "miek.nl.", "stdin")

	for _, tc := range dnsTestCases {
		resp := new(responseWriter)
		router.ServeDNS(resp, &Request{Msg: tc.Msg()})
		sortAndCheck(t, &resp.msg, tc)
	}
}

func BenchmarkLookup(b *testing.B) {
	const s = `
$TTL    30M
$ORIGIN miek.nl.
@       IN      SOA     linode.atoom.net. miek.miek.nl. (
                             1282630057 ; Serial
                             4H         ; Refresh
                             1H         ; Retry
                             7D         ; Expire
                             4H )       ; Negative Cache TTL
                IN      NS      linode.atoom.net.
                IN      NS      ns-ext.nlnetlabs.nl.
                IN      NS      omval.tednet.nl.
                IN      NS      ext.ns.whyscream.net.
                IN      MX      1  aspmx.l.google.com.
                IN      MX      5  alt1.aspmx.l.google.com.
                IN      MX      5  alt2.aspmx.l.google.com.
                IN      MX      10 aspmx2.googlemail.com.
                IN      MX      10 aspmx3.googlemail.com.
		IN      A       139.162.196.78
		IN      AAAA    2a01:7e00::f03c:91ff:fef1:6735
a               IN      A       139.162.196.78
                IN      AAAA    2a01:7e00::f03c:91ff:fef1:6735
www             IN      CNAME   a
archive         IN      CNAME   a
srv		IN	SRV     10 10 8080 a.miek.nl.
mx		IN	MX      10 a.miek.nl.`

	router := New()
	router.HandleZone(strings.NewReader(s), "miek.nl.", "stdin")
	resp := new(responseWriter)

	tc := testCase{
		Qname: "www.miek.nl.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			cname("www.miek.nl.	1800	IN	CNAME	a.miek.nl."),
			a("a.miek.nl.	1800	IN	A	139.162.196.78"),
		},
	}
	req := &Request{Msg: tc.Msg()}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		router.ServeDNS(resp, req)
	}
}

// rrSet represents a list of RRs.
type rrSet []dns.RR

func (p rrSet) Len() int           { return len(p) }
func (p rrSet) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p rrSet) Less(i, j int) bool { return p[i].String() < p[j].String() }

func a(rr string) *dns.A           { r, _ := dns.NewRR(rr); return r.(*dns.A) }
func aaaa(rr string) *dns.AAAA     { r, _ := dns.NewRR(rr); return r.(*dns.AAAA) }
func cname(rr string) *dns.CNAME   { r, _ := dns.NewRR(rr); return r.(*dns.CNAME) }
func dname(rr string) *dns.DNAME   { r, _ := dns.NewRR(rr); return r.(*dns.DNAME) }
func srv(rr string) *dns.SRV       { r, _ := dns.NewRR(rr); return r.(*dns.SRV) }
func soa(rr string) *dns.SOA       { r, _ := dns.NewRR(rr); return r.(*dns.SOA) }
func ns(rr string) *dns.NS         { r, _ := dns.NewRR(rr); return r.(*dns.NS) }
func ptr(rr string) *dns.PTR       { r, _ := dns.NewRR(rr); return r.(*dns.PTR) }
func txt(rr string) *dns.TXT       { r, _ := dns.NewRR(rr); return r.(*dns.TXT) }
func mx(rr string) *dns.MX         { r, _ := dns.NewRR(rr); return r.(*dns.MX) }
func rrsig(rr string) *dns.RRSIG   { r, _ := dns.NewRR(rr); return r.(*dns.RRSIG) }
func nsec(rr string) *dns.NSEC     { r, _ := dns.NewRR(rr); return r.(*dns.NSEC) }
func dnskey(rr string) *dns.DNSKEY { r, _ := dns.NewRR(rr); return r.(*dns.DNSKEY) }
func ds(rr string) *dns.DS         { r, _ := dns.NewRR(rr); return r.(*dns.DS) }
func opt(bufsize int, do bool) *dns.OPT {
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetVersion(0)
	o.SetUDPSize(uint16(bufsize))
	if do {
		o.SetDo()
	}
	return o
}

// testCase represents a test case that encapsulates various data from a query and response.
// Note that is the TTL of a record is 303 we don't compare it with the TTL.
type testCase struct {
	Qname  string
	Qtype  uint16
	Rcode  int
	Do     bool
	Answer []dns.RR
	Ns     []dns.RR
	Extra  []dns.RR
	Error  error
}

// Msg returns a *dns.Msg embedded in c.
func (c testCase) Msg() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(c.Qname), c.Qtype)
	if c.Do {
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		o.SetDo()
		o.SetUDPSize(4096)
		m.Extra = []dns.RR{o}
	}
	return m
}

// header test if the header in resp matches the header as defined in tc.
func header(t *testing.T, tc testCase, resp *dns.Msg) bool {
	if resp.Rcode != tc.Rcode {
		t.Errorf("rcode is %q, expected %q", dns.RcodeToString[resp.Rcode], dns.RcodeToString[tc.Rcode])
		return false
	}

	if len(resp.Answer) != len(tc.Answer) {
		t.Errorf("answer for %q contained %d results, %d expected", tc.Qname, len(resp.Answer), len(tc.Answer))
		return false
	}
	if len(resp.Ns) != len(tc.Ns) {
		t.Errorf("authority for %q contained %d results, %d expected", tc.Qname, len(resp.Ns), len(tc.Ns))
		return false
	}
	if len(resp.Extra) != len(tc.Extra) {
		t.Errorf("additional for %q contained %d results, %d expected", tc.Qname, len(resp.Extra), len(tc.Extra))
		return false
	}
	return true
}

// section tests if the the section in tc matches rr.
func section(t *testing.T, tc testCase, sec int, rr []dns.RR) bool {
	section := []dns.RR{}
	switch sec {
	case 0:
		section = tc.Answer
	case 1:
		section = tc.Ns
	case 2:
		section = tc.Extra
	}

	for i, a := range rr {
		if a.Header().Name != section[i].Header().Name {
			t.Errorf("rr %d should have a Header Name of %q, but has %q", i, section[i].Header().Name, a.Header().Name)
			return false
		}
		// 303 signals: don't care what the ttl is.
		if section[i].Header().Ttl != 303 && a.Header().Ttl != section[i].Header().Ttl {
			if _, ok := section[i].(*dns.OPT); !ok {
				// we check edns0 bufize on this one
				t.Errorf("rr %d should have a Header TTL of %d, but has %d", i, section[i].Header().Ttl, a.Header().Ttl)
				return false
			}
		}
		if a.Header().Rrtype != section[i].Header().Rrtype {
			t.Errorf("rr %d should have a header rr type of %d, but has %d", i, section[i].Header().Rrtype, a.Header().Rrtype)
			return false
		}

		switch x := a.(type) {
		case *dns.SRV:
			if x.Priority != section[i].(*dns.SRV).Priority {
				t.Errorf("rr %d should have a Priority of %d, but has %d", i, section[i].(*dns.SRV).Priority, x.Priority)
				return false
			}
			if x.Weight != section[i].(*dns.SRV).Weight {
				t.Errorf("rr %d should have a Weight of %d, but has %d", i, section[i].(*dns.SRV).Weight, x.Weight)
				return false
			}
			if x.Port != section[i].(*dns.SRV).Port {
				t.Errorf("rr %d should have a Port of %d, but has %d", i, section[i].(*dns.SRV).Port, x.Port)
				return false
			}
			if x.Target != section[i].(*dns.SRV).Target {
				t.Errorf("rr %d should have a Target of %q, but has %q", i, section[i].(*dns.SRV).Target, x.Target)
				return false
			}
		case *dns.RRSIG:
			if x.TypeCovered != section[i].(*dns.RRSIG).TypeCovered {
				t.Errorf("rr %d should have a TypeCovered of %d, but has %d", i, section[i].(*dns.RRSIG).TypeCovered, x.TypeCovered)
				return false
			}
			if x.Labels != section[i].(*dns.RRSIG).Labels {
				t.Errorf("rr %d should have a Labels of %d, but has %d", i, section[i].(*dns.RRSIG).Labels, x.Labels)
				return false
			}
			if x.SignerName != section[i].(*dns.RRSIG).SignerName {
				t.Errorf("rr %d should have a SignerName of %s, but has %s", i, section[i].(*dns.RRSIG).SignerName, x.SignerName)
				return false
			}
		case *dns.NSEC:
			if x.NextDomain != section[i].(*dns.NSEC).NextDomain {
				t.Errorf("rr %d should have a NextDomain of %s, but has %s", i, section[i].(*dns.NSEC).NextDomain, x.NextDomain)
				return false
			}
			// TypeBitMap
		case *dns.A:
			if x.A.String() != section[i].(*dns.A).A.String() {
				t.Errorf("rr %d should have a Address of %q, but has %q", i, section[i].(*dns.A).A.String(), x.A.String())
				return false
			}
		case *dns.AAAA:
			if x.AAAA.String() != section[i].(*dns.AAAA).AAAA.String() {
				t.Errorf("rr %d should have a Address of %q, but has %q", i, section[i].(*dns.AAAA).AAAA.String(), x.AAAA.String())
				return false
			}
		case *dns.TXT:
			for j, txt := range x.Txt {
				if txt != section[i].(*dns.TXT).Txt[j] {
					t.Errorf("rr %d should have a Txt of %q, but has %q", i, section[i].(*dns.TXT).Txt[j], txt)
					return false
				}
			}
		case *dns.SOA:
			tt := section[i].(*dns.SOA)
			if x.Ns != tt.Ns {
				t.Errorf("SOA nameserver should be %q, but is %q", tt.Ns, x.Ns)
				return false
			}
		case *dns.PTR:
			tt := section[i].(*dns.PTR)
			if x.Ptr != tt.Ptr {
				t.Errorf("PTR ptr should be %q, but is %q", tt.Ptr, x.Ptr)
				return false
			}
		case *dns.CNAME:
			tt := section[i].(*dns.CNAME)
			if x.Target != tt.Target {
				t.Errorf("CNAME target should be %q, but is %q", tt.Target, x.Target)
				return false
			}
		case *dns.MX:
			tt := section[i].(*dns.MX)
			if x.Mx != tt.Mx {
				t.Errorf("MX Mx should be %q, but is %q", tt.Mx, x.Mx)
				return false
			}
			if x.Preference != tt.Preference {
				t.Errorf("MX Preference should be %q, but is %q", tt.Preference, x.Preference)
				return false
			}
		case *dns.NS:
			tt := section[i].(*dns.NS)
			if x.Ns != tt.Ns {
				t.Errorf("NS nameserver should be %q, but is %q", tt.Ns, x.Ns)
				return false
			}
		case *dns.OPT:
			tt := section[i].(*dns.OPT)
			if x.UDPSize() != tt.UDPSize() {
				t.Errorf("OPT UDPSize should be %d, but is %d", tt.UDPSize(), x.UDPSize())
				return false
			}
			if x.Do() != tt.Do() {
				t.Errorf("OPT DO should be %t, but is %t", tt.Do(), x.Do())
				return false
			}
		}
	}
	return true
}

// cnameOrder makes sure that CNAMES do not appear after their target records
func cnameOrder(t *testing.T, res *dns.Msg) {
	for i, c := range res.Answer {
		if c.Header().Rrtype != dns.TypeCNAME {
			continue
		}
		for _, a := range res.Answer[:i] {
			if a.Header().Name != c.(*dns.CNAME).Target {
				continue
			}
			t.Errorf("CNAME found after target record\n")
			t.Logf("%v\n", res)

		}
	}
}

// sortAndCheck sorts resp and the checks the header and three sections against the testcase in tc.
func sortAndCheck(t *testing.T, resp *dns.Msg, tc testCase) {
	sort.Sort(rrSet(resp.Answer))
	sort.Sort(rrSet(resp.Ns))
	sort.Sort(rrSet(resp.Extra))

	if !header(t, tc, resp) {
		t.Logf("%v\n", resp)
		return
	}

	if !section(t, tc, 0, resp.Answer) {
		t.Logf("%v\n", resp)
		return
	}
	if !section(t, tc, 1, resp.Ns) {
		t.Logf("%v\n", resp)
		return

	}
	if !section(t, tc, 2, resp.Extra) {
		t.Logf("%v\n", resp)
		return
	}
}
