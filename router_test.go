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
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestCanonicalOrder(t *testing.T) {
	input := []string{
		"example.",
		"a.example.",
		"yljkjljk.a.example.",
		"z.a.example.",
		"zabc.a.example.",
		"z.example.",
		"\001.z.example.",
		"*.z.example.",
		"\200.z.example.",
	}

	names := make([]string, 0, len(input))
	for _, s := range input {
		names = append(names, newIndexableName(s))
	}
	order := make(canonicalOrder, 0, len(names))
	for _, i := range rand.Perm(len(names)) {
		order = append(order, names[i])
	}
	sort.Sort(order)
	for i := 0; i < len(order); i++ {
		for j := i; j < len(order); j++ {
			if canonicalOrderLess(order[j], order[i]) {
				t.Errorf("expected %s <= %s, got against", order[i], order[j])
			}
		}
	}
	if s, found := order.Previous(".example.a"); !found {
		t.Error(".example.a: should be found, got", s)
	}
	if s, found := order.Previous(".example"); !found {
		t.Error(".example: should be found, got", s)
	}

	revert := make([]string, 0, len(order))
	for _, s := range order {
		revert = append(revert, indexable(s))
	}
	if !reflect.DeepEqual(input, revert) {
		t.Error("got wrong order:", revert)
	}
}

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
	router.HandleFunc(":a.:b.org", func(w ResponseWriter, r *Request) {
		routed = true
		if want, v := "www", r.Params().ByName("a"); v != want {
			t.Fatalf("wrong wildcard values: want %v, got %v", want, v)
		}
		if want, v := "example", r.Params().ByName("b"); v != want {
			t.Fatalf("wrong wildcard values: want %v, got %v", want, v)
		}
		if want, v := "www", r.Params()[0].Value; v != want {
			t.Fatalf("wrong wildcard values: want %v, got %v", want, v)
		}
		if want, v := "example", r.Params()[1].Value; v != want {
			t.Fatalf("wrong wildcard values: want %v, got %v", want, v)
		}
	})

	w := new(responseWriter)
	router.ServeDNS(w, NewRequest("www.example.org", dns.TypeA))

	if !routed {
		t.Fatal("routing failed")
	}
}

func TestRouterChaining(t *testing.T) {
	router1 := New()
	router2 := New()
	router1.NoName = router2

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

	panicHandler := func(h Handler) Handler {
		return HandlerFunc(func(w ResponseWriter, r *Request) {
			defer func() {
				if v := recover(); v != nil {
					panicHandled = true
				}
			}()
			h.ServeDNS(w, r)
		})
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

	panicHandler(router).ServeDNS(w, req)

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
	handles, _, _ := router.Lookup("nope", dns.ClassINET)
	if handles != nil {
		t.Fatalf("Got handles for unregistered pattern: %v", handles)
	}

	// insert route and try again
	router.HandleFunc(":name.user", wantHandle)

	handlers, params, _ := router.Lookup("gopher.user", dns.ClassINET)
	if handlers == nil {
		t.Fatal("Got no handlers!")
	} else {
		handlers.ServeDNS(nil, nil)
		if !routed {
			t.Fatal("Routing failed!")
		}
	}

	if !reflect.DeepEqual(params, wantParams) {
		t.Fatalf("Wrong parameter values: want %v, got %v", wantParams, params)
	}

	handlers, _, _ = router.Lookup(".gopher.user", dns.ClassINET)
	if handlers != nil {
		t.Fatalf("Got handlers for unregistered pattern: %v", handlers)
	}

	handlers, _, _ = router.Lookup("nope", dns.ClassINET)
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
		req := &Request{Msg: tc.Msg()}
		ChainHandler(router, NxHandler, ExtraHandler, CnameHandler).ServeDNS(resp, req)
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
		req := &Request{Msg: tc.Msg()}
		ChainHandler(router, DefaultScheme...).ServeDNS(resp, req)
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

	tc := testCase{
		Qname: "www.miek.nl.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			cname("www.miek.nl.	1800	IN	CNAME	a.miek.nl."),
			a("a.miek.nl.	1800	IN	A	139.162.196.78"),
		},
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		resp := new(responseWriter)
		req := &Request{Msg: tc.Msg()}
		ChainHandler(router, CnameHandler).ServeDNS(resp, req)
	}
}

func TestLookupDNSSEC(t *testing.T) {
	const s = `
; File written on Sun Mar 27 04:13:01 2016
; dnssec_signzone version 9.10.3-P4-Ubuntu
miek.nl.		1800	IN SOA	linode.atoom.net. miek.miek.nl. (
					1459051981 ; serial
					14400      ; refresh (4 hours)
					3600       ; retry (1 hour)
					604800     ; expire (1 week)
					14400      ; minimum (4 hours)
					)
			1800	RRSIG	SOA 8 2 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					FIrzy07acBzrf6kNW13Ypmq/ahojoMqOj0qJ
					ixTevTvwOEcVuw9GlJoYIHTYg+hm1sZHtx9K
					RiVmYsm8SHKsJA1WzixtT4K7vQvM+T+qbeOJ
					xA6YTivKUcGRWRXQlOTUAlHS/KqBEfmxKgRS
					68G4oOEClFDSJKh7RbtyQczy1dc= )
			1800	NS	ext.ns.whyscream.net.
			1800	NS	omval.tednet.nl.
			1800	NS	linode.atoom.net.
			1800	NS	ns-ext.nlnetlabs.nl.
			1800	RRSIG	NS 8 2 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					ZLtsQhwaz+CwrgzgFiEAqbqS/JH65MYjziA3
					6EXwlGDy41lcfGm71PpxA7cDzFhWNkJNk4QF
					q48wtpP4IGPPpHbnJHKDUXj6se7S+ylAGbS+
					VgVJ4YaVcE6xA9ZVhVpz8CSSjeH34vmqq9xj
					zmFjofuDvraZflHfNpztFoR1Vxs= )
			1800	A	139.162.196.78
			1800	RRSIG	A 8 2 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					hl+6Q075tsCkxIqbop8zZ6U8rlFvooz7Izzx
					MgCZYVLcg75El28EXKIhBfRb1dPaKbd+v+AD
					wrJMHL131pY5sU2Ly05K+7CqmmyaXgDaVsKS
					rSw/TbhGDIItBemeseeuXGAKAbY2+gE7kNN9
					mZoQ9hRB3SrxE2jhctv66DzYYQQ= )
			1800	MX	1 aspmx.l.google.com.
			1800	MX	5 alt1.aspmx.l.google.com.
			1800	MX	5 alt2.aspmx.l.google.com.
			1800	MX	10 aspmx2.googlemail.com.
			1800	MX	10 aspmx3.googlemail.com.
			1800	RRSIG	MX 8 2 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					kLqG+iOrKSzms1H9Et9me8Zts1rbyeCFSVQD
					G9is/u6ec3Lqg2vwJddf/yRsjVpVgadWSAkc
					GSDuD2dK8oBeP24axWc3Z1OY2gdMI7w+PKWT
					Z+pjHVjbjM47Ii/a6jk5SYeOwpGMsdEwhtTP
					vk2O2WGljifqV3uE7GshF5WNR10= )
			1800	AAAA	2a01:7e00::f03c:91ff:fef1:6735
			1800	RRSIG	AAAA 8 2 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					SsRTHytW4YTAuHovHQgfIMhNwMtMp4gaAU/Z
					lgTO+IkBb9y9F8uHrf25gG6RqA1bnGV/gezV
					NU5negXm50bf1BNcyn3aCwEbA0rCGYIL+nLJ
					szlBVbBu6me/Ym9bbJlfgfHRDfsVy2ZkNL+B
					jfNQtGCSDoJwshjcqJlfIVSardo= )
			14400	NSEC	a.miek.nl. A NS SOA MX AAAA RRSIG NSEC DNSKEY
			14400	RRSIG	NSEC 8 2 14400 (
					20160426031301 20160327031301 12051 miek.nl.
					mFfc3r/9PSC1H6oSpdC+FDy/Iu02W2Tf0x+b
					n6Lpe1gCC1uvcSUrrmBNlyAWRr5Zm+ZXssEb
					cKddRGiu/5sf0bUWrs4tqokL/HUl10X/sBxb
					HfwNAeD7R7+CkpMv67li5AhsDgmQzpX2r3P6
					/6oZyLvODGobysbmzeWM6ckE8IE= )
			1800	DNSKEY	256 3 8 (
					AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6
					E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5EC
					IoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb
					2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXH
					Py7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz
					) ; ZSK; alg = RSASHA256; key id = 12051
			1800	DNSKEY	257 3 8 (
					AwEAAcWdjBl4W4wh/hPxMDcBytmNCvEngIgB
					9Ut3C2+QI0oVz78/WK9KPoQF7B74JQ/mjO4f
					vIncBmPp6mFNxs9/WQX0IXf7oKviEVOXLjct
					R4D1KQLX0wprvtUIsQFIGdXaO6suTT5eDbSd
					6tTwu5xIkGkDmQhhH8OQydoEuCwV245ZwF/8
					AIsqBYDNQtQ6zhd6jDC+uZJXg/9LuPOxFHbi
					MTjp6j3CCW0kHbfM/YHZErWWtjPj3U3Z7knQ
					SIm5PO5FRKBEYDdr5UxWJ/1/20SrzI3iztvP
					wHDsA2rdHm/4YRzq7CvG4N0t9ac/T0a0Sxba
					/BUX2UVPWaIVBdTRBtgHi0s=
					) ; KSK; alg = RSASHA256; key id = 33694
			1800	RRSIG	DNSKEY 8 2 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					o/D6o8+/bNGQyyRvwZ2hM0BJ+3HirvNjZoko
					yGhGe9sPSrYU39WF3JVIQvNJFK6W3/iwlKir
					TPOeYlN6QilnztFq1vpCxwj2kxJaIJhZecig
					LsKxY/fOHwZlIbBLZZadQG6JoGRLHnImSzpf
					xtyVaXQtfnJFC07HHt9np3kICfE= )
			1800	RRSIG	DNSKEY 8 2 1800 (
					20160426031301 20160327031301 33694 miek.nl.
					Ak/mbbQVQV+nUgw5Sw/c+TSoYqIwbLARzuNE
					QJvJNoRR4tKVOY6qSxQv+j5S7vzyORZ+yeDp
					NlEa1T9kxZVBMABoOtLX5kRqZncgijuH8fxb
					L57Sv2IzINI9+DOcy9Q9p9ygtwYzQKrYoNi1
					0hwHi6emGkVG2gGghruMinwOJASGgQy487Yd
					eIpcEKJRw73nxd2le/4/Vafy+mBpKWOczfYi
					5m9MSSxcK56NFYjPG7TvdIw0m70F/smY9KBP
					pGWEdzRQDlqfZ4fpDaTAFGyRX0mPFzMbs1DD
					3hQ4LHUSi/NgQakdH9eF42EVEDeL4cI69K98
					6NNk6X9TRslO694HKw== )
a.miek.nl.		1800	IN A	139.162.196.78
			1800	RRSIG	A 8 3 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					lxLotCjWZ3kikNNcePu6HOCqMHDINKFRJRD8
					laz2KQ9DKtgXPdnRw5RJvVITSj8GUVzw1ec1
					CYVEKu/eMw/rc953Zns528QBypGPeMNLe2vu
					C6a6UhZnGHA48dSd9EX33eSJs0MP9xsC9csv
					LGdzYmv++eslkKxkhSOk2j/hTxk= )
			1800	AAAA	2a01:7e00::f03c:91ff:fef1:6735
			1800	RRSIG	AAAA 8 3 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					ji3QMlaUzlK85ppB5Pc+y2WnfqOi6qrm6dm1
					bXgsEov/5UV1Lmcv8+Y5NBbTbBlXGlWcpqNp
					uWpf9z3lbguDWznpnasN2MM8t7yxo/Cr7WRf
					QCzui7ewpWiA5hq7j0kVbM4nnDc6cO+U93hO
					mMhVbeVI70HM2m0HaHkziEyzVZk= )
			14400	NSEC	archive.miek.nl. A AAAA RRSIG NSEC
			14400	RRSIG	NSEC 8 3 14400 (
					20160426031301 20160327031301 12051 miek.nl.
					GqnF6cut/KCxbnJj27MCjjVGkjObV0hLhHOP
					E1/GXAUTEKG6BWxJq8hidS3p/yrOmP5PEL9T
					4FjBp0/REdVmGpuLaiHyMselES82p/uMMdY5
					QqRM6LHhZdO1zsRbyzOZbm5MsW6GR7K2kHlX
					9TdBIULiRRGPQ1QGQE1ipmSHEao= )
archive.miek.nl.	1800	IN CNAME a.miek.nl.
			1800	RRSIG	CNAME 8 3 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					s4zVJiDrVuUiUFr8CNQLuXYYfpqpl8rovL50
					BYsub/xK756NENiOTAOjYH6KYg7RSzsygJjV
					YQwXolZly2/KXAr48SCtxzkGFxLexxiKcFaj
					vm7ZDl7Btoa5l68qmBcxOX5E/W0IKITi4PNK
					mhBs7dlaf0IbPGNgMxae72RosxM= )
			14400	NSEC	go.dns.miek.nl. CNAME RRSIG NSEC
			14400	RRSIG	NSEC 8 3 14400 (
					20160426031301 20160327031301 12051 miek.nl.
					jEp7LsoK++/PRFh2HieLzasA1jXBpp90NyDf
					RfpfOxdM69yRKfvXMc2bazIiMuDhxht79dGI
					Gj02cn1cvX60SlaHkeFtqTdJcHdK9rbI65EK
					YHFZFzGh9XVnuMJKpUsm/xS1dnUSAnXN8q+0
					xBlUDlQpsAFv/cx8lcp4do5fWXg= )
go.dns.miek.nl.		1800	IN TXT	"Hello!"
			1800	RRSIG	TXT 8 4 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					O0uo1NsXTq2TTfgOmGbHQQEchrcpllaDAMMX
					dTDizw3t+vZ5SR32qJ8W7y6VXLgUqJgcdRxS
					Fou1pp+t5juRZSQ0LKgxMpZAgHorkzPvRf1b
					E9eBKrDSuLGagsQRwHeldFGFgsXtCbf07vVH
					zoKR8ynuG4/cAoY0JzMhCts+56U= )
			14400	NSEC	www.miek.nl. TXT RRSIG NSEC
			14400	RRSIG	NSEC 8 4 14400 (
					20160426031301 20160327031301 12051 miek.nl.
					BW6qo7kYe3Z+Y0ebaVTWTy1c3bpdf8WUEoXq
					WDQxLDEj2fFiuEBDaSN5lTWRg3wj8kZmr6Uk
					LvX0P29lbATFarIgkyiAdbOEdaf88nMfqBW8
					z2T5xrPQcN0F13uehmv395yAJs4tebRxErMl
					KdkVF0dskaDvw8Wo3YgjHUf6TXM= )
www.miek.nl.		1800	IN CNAME a.miek.nl.
			1800	RRSIG	CNAME 8 3 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					MiQQh2lScoNiNVZmMJaypS+wDL2Lar4Zw1zF
					Uo4tL16BfQOt7yl8gXdAH2JMFqoKAoIdM2K6
					XwFOwKTOGSW0oNCOcaE7ts+1Z1U0H3O2tHfq
					FAzfg1s9pQ5zxk8J/bJgkVIkw2/cyB0y1/PK
					EmIqvChBSb4NchTuMCSqo63LJM8= )
			14400	NSEC	miek.nl. CNAME RRSIG NSEC
			14400	RRSIG	NSEC 8 3 14400 (
					20160426031301 20160327031301 12051 miek.nl.
					OPPZ8iaUPrVKEP4cqeCiiv1WLRAY30GRIhc/
					me0gBwFkbmTEnvB+rUp831OJZDZBNKv4QdZj
					Uyc26wKUOQeUyMJqv4IRDgxH7nq9GB5JRjYZ
					IVxtGD1aqWLXz+8aMaf9ARJjtYUd3K4lt8Wz
					LbJSo5Wdq7GOWqhgkY5n3XD0/FA= )`

	var auth = []dns.RR{
		ns("miek.nl.	1800	IN	NS	ext.ns.whyscream.net."),
		ns("miek.nl.	1800	IN	NS	linode.atoom.net."),
		ns("miek.nl.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
		ns("miek.nl.	1800	IN	NS	omval.tednet.nl."),
		rrsig("miek.nl.	1800	IN	RRSIG	NS 8 2 1800 20160426031301 20160327031301 12051 miek.nl. ZLtsQhwazbqSpztFoR1Vxs="),
	}

	var dnsTestCases = []testCase{
		{
			Qname: "miek.nl.", Qtype: dns.TypeSOA, Do: true,
			Answer: []dns.RR{
				rrsig("miek.nl.	1800	IN	RRSIG	SOA 8 2 1800 20160426031301 20160327031301 12051 miek.nl. FIrzy07acBbtyQczy1dc="),
				soa("miek.nl.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"),
			},
			Ns:    auth,
			Extra: []dns.RR{opt(4096, true)},
		},
		{
			Qname: "miek.nl.", Qtype: dns.TypeAAAA, Do: true,
			Answer: []dns.RR{
				aaaa("miek.nl.	1800	IN	AAAA	2a01:7e00::f03c:91ff:fef1:6735"),
				rrsig("miek.nl.	1800	IN	RRSIG	AAAA 8 2 1800 20160426031301 20160327031301 12051 miek.nl. SsRT="),
			},
			Ns:    auth,
			Extra: []dns.RR{opt(4096, true)},
		},
		{
			Qname: "miek.nl.", Qtype: dns.TypeNS, Do: true,
			Answer: []dns.RR{
				ns("miek.nl.	1800	IN	NS	ext.ns.whyscream.net."),
				ns("miek.nl.	1800	IN	NS	linode.atoom.net."),
				ns("miek.nl.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
				ns("miek.nl.	1800	IN	NS	omval.tednet.nl."),
				rrsig("miek.nl.	1800	IN	RRSIG	NS 8 2 1800 20160426031301 20160327031301 12051 miek.nl. ZLtsQhwaz+lHfNpztFoR1Vxs="),
			},
			Extra: []dns.RR{opt(4096, true)},
		},
		{
			Qname: "miek.nl.", Qtype: dns.TypeMX, Do: true,
			Answer: []dns.RR{
				mx("miek.nl.	1800	IN	MX	1 aspmx.l.google.com."),
				mx("miek.nl.	1800	IN	MX	10 aspmx2.googlemail.com."),
				mx("miek.nl.	1800	IN	MX	10 aspmx3.googlemail.com."),
				mx("miek.nl.	1800	IN	MX	5 alt1.aspmx.l.google.com."),
				mx("miek.nl.	1800	IN	MX	5 alt2.aspmx.l.google.com."),
				rrsig("miek.nl.	1800	IN	RRSIG	MX 8 2 1800 20160426031301 20160327031301 12051 miek.nl. kLqG+iOr="),
			},
			Ns:    auth,
			Extra: []dns.RR{opt(4096, true)},
		},
		{
			Qname: "www.miek.nl.", Qtype: dns.TypeA, Do: true,
			Answer: []dns.RR{
				a("a.miek.nl.	1800	IN	A	139.162.196.78"),
				rrsig("a.miek.nl.	1800	IN	RRSIG	A 8 3 1800 20160426031301 20160327031301 12051 miek.nl. lxLotCjWZ3kihTxk="),
				cname("www.miek.nl.	1800	IN	CNAME	a.miek.nl."),
				rrsig("www.miek.nl. 1800	RRSIG	CNAME 8 3 1800 20160426031301 20160327031301 12051 miek.nl.  NVZmMJaypS+wDL2Lar4Zw1zF"),
			},
			Ns:    auth,
			Extra: []dns.RR{opt(4096, true)},
		},
		{
			// NoData
			Qname: "a.miek.nl.", Qtype: dns.TypeSRV, Do: true,
			Ns: []dns.RR{
				nsec("a.miek.nl.	14400	IN	NSEC	archive.miek.nl. A AAAA RRSIG NSEC"),
				rrsig("a.miek.nl.	14400	IN	RRSIG	NSEC 8 3 14400 20160426031301 20160327031301 12051 miek.nl. GqnF6cutipmSHEao="),
				rrsig("miek.nl.	1800	IN	RRSIG	SOA 8 2 1800 20160426031301 20160327031301 12051 miek.nl. FIrzy07acBbtyQczy1dc="),
				soa("miek.nl.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"),
			},
			Extra: []dns.RR{opt(4096, true)},
		},
		{
			Qname: "b.miek.nl.", Qtype: dns.TypeA, Do: true,
			Rcode: dns.RcodeNameError,
			Ns: []dns.RR{
				nsec("archive.miek.nl.	14400	IN	NSEC	go.dns.miek.nl. CNAME RRSIG NSEC"),
				rrsig("archive.miek.nl.	14400	IN	RRSIG	NSEC 8 3 14400 20160426031301 20160327031301 12051 miek.nl. jEpx8lcp4do5fWXg="),
				nsec("miek.nl.	14400	IN	NSEC	a.miek.nl. A NS SOA MX AAAA RRSIG NSEC DNSKEY"),
				rrsig("miek.nl.	14400	IN	RRSIG	NSEC 8 2 14400 20160426031301 20160327031301 12051 miek.nl. mFfc3r/9PSC1H6oSpdC"),
				rrsig("miek.nl.	1800	IN	RRSIG	SOA 8 2 1800 20160426031301 20160327031301 12051 miek.nl. FIrzy07acBbtyQczy1dc="),
				soa("miek.nl.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"),
			},
			Extra: []dns.RR{opt(4096, true)},
		},
		{
			Qname: "b.blaat.miek.nl.", Qtype: dns.TypeA, Do: true,
			Rcode: dns.RcodeNameError,
			Ns: []dns.RR{
				nsec("archive.miek.nl.	14400	IN	NSEC	go.dns.miek.nl. CNAME RRSIG NSEC"),
				rrsig("archive.miek.nl.	14400	IN	RRSIG	NSEC 8 3 14400 20160426031301 20160327031301 12051 miek.nl. jEpx8lcp4do5fWXg="),
				nsec("miek.nl.	14400	IN	NSEC	a.miek.nl. A NS SOA MX AAAA RRSIG NSEC DNSKEY"),
				rrsig("miek.nl.	14400	IN	RRSIG	NSEC 8 2 14400 20160426031301 20160327031301 12051 miek.nl. mFfc3r/9PSC1H6oSpdC"),
				rrsig("miek.nl.	1800	IN	RRSIG	SOA 8 2 1800 20160426031301 20160327031301 12051 miek.nl. FIrzy07acBbtyQczy1dc="),
				soa("miek.nl.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"),
			},
			Extra: []dns.RR{opt(4096, true)},
		},
		{
			Qname: "b.a.miek.nl.", Qtype: dns.TypeA, Do: true,
			Rcode: dns.RcodeNameError,
			Ns: []dns.RR{
				// dedupped NSEC, because 1 nsec tells all
				nsec("a.miek.nl.	14400	IN	NSEC	archive.miek.nl. A AAAA RRSIG NSEC"),
				rrsig("a.miek.nl.	14400	IN	RRSIG	NSEC 8 3 14400 20160426031301 20160327031301 12051 miek.nl. GqnF6cut/RRGPQ1QGQE1ipmSHEao="),
				rrsig("miek.nl.	1800	IN	RRSIG	SOA 8 2 1800 20160426031301 20160327031301 12051 miek.nl. FIrzy07acBbtyQczy1dc="),
				soa("miek.nl.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"),
			},
			Extra: []dns.RR{opt(4096, true)},
		},
		{
			Qname: "github.com.", Qtype: dns.TypeA, Do: true,
			Rcode: dns.RcodeRefused,
			Extra: []dns.RR{opt(4096, true)},
		},
	}

	router := New()
	router.HandleZone(strings.NewReader(s), "miek.nl.", "stdin")

	for _, tc := range dnsTestCases {
		resp := new(responseWriter)
		req := &Request{Msg: tc.Msg()}
		ChainHandler(router, DefaultScheme...).ServeDNS(resp, req)
		sortAndCheck(t, &resp.msg, tc)
	}
}

func BenchmarkLookupDNSSEC(b *testing.B) {
	const s = `
; File written on Sun Mar 27 04:13:01 2016
; dnssec_signzone version 9.10.3-P4-Ubuntu
miek.nl.		1800	IN SOA	linode.atoom.net. miek.miek.nl. (
					1459051981 ; serial
					14400      ; refresh (4 hours)
					3600       ; retry (1 hour)
					604800     ; expire (1 week)
					14400      ; minimum (4 hours)
					)
			1800	RRSIG	SOA 8 2 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					FIrzy07acBzrf6kNW13Ypmq/ahojoMqOj0qJ
					ixTevTvwOEcVuw9GlJoYIHTYg+hm1sZHtx9K
					RiVmYsm8SHKsJA1WzixtT4K7vQvM+T+qbeOJ
					xA6YTivKUcGRWRXQlOTUAlHS/KqBEfmxKgRS
					68G4oOEClFDSJKh7RbtyQczy1dc= )
			1800	NS	ext.ns.whyscream.net.
			1800	NS	omval.tednet.nl.
			1800	NS	linode.atoom.net.
			1800	NS	ns-ext.nlnetlabs.nl.
			1800	RRSIG	NS 8 2 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					ZLtsQhwaz+CwrgzgFiEAqbqS/JH65MYjziA3
					6EXwlGDy41lcfGm71PpxA7cDzFhWNkJNk4QF
					q48wtpP4IGPPpHbnJHKDUXj6se7S+ylAGbS+
					VgVJ4YaVcE6xA9ZVhVpz8CSSjeH34vmqq9xj
					zmFjofuDvraZflHfNpztFoR1Vxs= )
			1800	A	139.162.196.78
			1800	RRSIG	A 8 2 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					hl+6Q075tsCkxIqbop8zZ6U8rlFvooz7Izzx
					MgCZYVLcg75El28EXKIhBfRb1dPaKbd+v+AD
					wrJMHL131pY5sU2Ly05K+7CqmmyaXgDaVsKS
					rSw/TbhGDIItBemeseeuXGAKAbY2+gE7kNN9
					mZoQ9hRB3SrxE2jhctv66DzYYQQ= )
			1800	MX	1 aspmx.l.google.com.
			1800	MX	5 alt1.aspmx.l.google.com.
			1800	MX	5 alt2.aspmx.l.google.com.
			1800	MX	10 aspmx2.googlemail.com.
			1800	MX	10 aspmx3.googlemail.com.
			1800	RRSIG	MX 8 2 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					kLqG+iOrKSzms1H9Et9me8Zts1rbyeCFSVQD
					G9is/u6ec3Lqg2vwJddf/yRsjVpVgadWSAkc
					GSDuD2dK8oBeP24axWc3Z1OY2gdMI7w+PKWT
					Z+pjHVjbjM47Ii/a6jk5SYeOwpGMsdEwhtTP
					vk2O2WGljifqV3uE7GshF5WNR10= )
			1800	AAAA	2a01:7e00::f03c:91ff:fef1:6735
			1800	RRSIG	AAAA 8 2 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					SsRTHytW4YTAuHovHQgfIMhNwMtMp4gaAU/Z
					lgTO+IkBb9y9F8uHrf25gG6RqA1bnGV/gezV
					NU5negXm50bf1BNcyn3aCwEbA0rCGYIL+nLJ
					szlBVbBu6me/Ym9bbJlfgfHRDfsVy2ZkNL+B
					jfNQtGCSDoJwshjcqJlfIVSardo= )
			14400	NSEC	a.miek.nl. A NS SOA MX AAAA RRSIG NSEC DNSKEY
			14400	RRSIG	NSEC 8 2 14400 (
					20160426031301 20160327031301 12051 miek.nl.
					mFfc3r/9PSC1H6oSpdC+FDy/Iu02W2Tf0x+b
					n6Lpe1gCC1uvcSUrrmBNlyAWRr5Zm+ZXssEb
					cKddRGiu/5sf0bUWrs4tqokL/HUl10X/sBxb
					HfwNAeD7R7+CkpMv67li5AhsDgmQzpX2r3P6
					/6oZyLvODGobysbmzeWM6ckE8IE= )
			1800	DNSKEY	256 3 8 (
					AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6
					E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5EC
					IoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb
					2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXH
					Py7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz
					) ; ZSK; alg = RSASHA256; key id = 12051
			1800	DNSKEY	257 3 8 (
					AwEAAcWdjBl4W4wh/hPxMDcBytmNCvEngIgB
					9Ut3C2+QI0oVz78/WK9KPoQF7B74JQ/mjO4f
	
				vIncBmPp6mFNxs9/WQX0IXf7oKviEVOXLjct
					R4D1KQLX0wprvtUIsQFIGdXaO6suTT5eDbSd
					6tTwu5xIkGkDmQhhH8OQydoEuCwV245ZwF/8
					AIsqBYDNQtQ6zhd6jDC+uZJXg/9LuPOxFHbi
					MTjp6j3CCW0kHbfM/YHZErWWtjPj3U3Z7knQ
					SIm5PO5FRKBEYDdr5UxWJ/1/20SrzI3iztvP
					wHDsA2rdHm/4YRzq7CvG4N0t9ac/T0a0Sxba
					/BUX2UVPWaIVBdTRBtgHi0s=
					) ; KSK; alg = RSASHA256; key id = 33694
			1800	RRSIG	DNSKEY 8 2 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					o/D6o8+/bNGQyyRvwZ2hM0BJ+3HirvNjZoko
					yGhGe9sPSrYU39WF3JVIQvNJFK6W3/iwlKir
					TPOeYlN6QilnztFq1vpCxwj2kxJaIJhZecig
					LsKxY/fOHwZlIbBLZZadQG6JoGRLHnImSzpf
					xtyVaXQtfnJFC07HHt9np3kICfE= )
			1800	RRSIG	DNSKEY 8 2 1800 (
					20160426031301 20160327031301 33694 miek.nl.
					Ak/mbbQVQV+nUgw5Sw/c+TSoYqIwbLARzuNE
					QJvJNoRR4tKVOY6qSxQv+j5S7vzyORZ+yeDp
					NlEa1T9kxZVBMABoOtLX5kRqZncgijuH8fxb
					L57Sv2IzINI9+DOcy9Q9p9ygtwYzQKrYoNi1
					0hwHi6emGkVG2gGghruMinwOJASGgQy487Yd
					eIpcEKJRw73nxd2le/4/Vafy+mBpKWOczfYi
					5m9MSSxcK56NFYjPG7TvdIw0m70F/smY9KBP
					pGWEdzRQDlqfZ4fpDaTAFGyRX0mPFzMbs1DD
					3hQ4LHUSi/NgQakdH9eF42EVEDeL4cI69K98
					6NNk6X9TRslO694HKw== )
a.miek.nl.		1800	IN A	139.162.196.78
			1800	RRSIG	A 8 3 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					lxLotCjWZ3kikNNcePu6HOCqMHDINKFRJRD8
					laz2KQ9DKtgXPdnRw5RJvVITSj8GUVzw1ec1
					CYVEKu/eMw/rc953Zns528QBypGPeMNLe2vu
					C6a6UhZnGHA48dSd9EX33eSJs0MP9xsC9csv
					LGdzYmv++eslkKxkhSOk2j/hTxk= )
			1800	AAAA	2a01:7e00::f03c:91ff:fef1:6735
			1800	RRSIG	AAAA 8 3 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					ji3QMlaUzlK85ppB5Pc+y2WnfqOi6qrm6dm1
					bXgsEov/5UV1Lmcv8+Y5NBbTbBlXGlWcpqNp
					uWpf9z3lbguDWznpnasN2MM8t7yxo/Cr7WRf
					QCzui7ewpWiA5hq7j0kVbM4nnDc6cO+U93hO
					mMhVbeVI70HM2m0HaHkziEyzVZk= )
			14400	NSEC	archive.miek.nl. A AAAA RRSIG NSEC
			14400	RRSIG	NSEC 8 3 14400 (
					20160426031301 20160327031301 12051 miek.nl.
					GqnF6cut/KCxbnJj27MCjjVGkjObV0hLhHOP
					E1/GXAUTEKG6BWxJq8hidS3p/yrOmP5PEL9T
					4FjBp0/REdVmGpuLaiHyMselES82p/uMMdY5
					QqRM6LHhZdO1zsRbyzOZbm5MsW6GR7K2kHlX
					9TdBIULiRRGPQ1QGQE1ipmSHEao= )
archive.miek.nl.	1800	IN CNAME a.miek.nl.
			1800	RRSIG	CNAME 8 3 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					s4zVJiDrVuUiUFr8CNQLuXYYfpqpl8rovL50
					BYsub/xK756NENiOTAOjYH6KYg7RSzsygJjV
					YQwXolZly2/KXAr48SCtxzkGFxLexxiKcFaj
					vm7ZDl7Btoa5l68qmBcxOX5E/W0IKITi4PNK
					mhBs7dlaf0IbPGNgMxae72RosxM= )
			14400	NSEC	go.dns.miek.nl. CNAME RRSIG NSEC
			14400	RRSIG	NSEC 8 3 14400 (
					20160426031301 20160327031301 12051 miek.nl.
					jEp7LsoK++/PRFh2HieLzasA1jXBpp90NyDf
					RfpfOxdM69yRKfvXMc2bazIiMuDhxht79dGI
					Gj02cn1cvX60SlaHkeFtqTdJcHdK9rbI65EK
					YHFZFzGh9XVnuMJKpUsm/xS1dnUSAnXN8q+0
					xBlUDlQpsAFv/cx8lcp4do5fWXg= )
go.dns.miek.nl.		1800	IN TXT	"Hello!"
			1800	RRSIG	TXT 8 4 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					O0uo1NsXTq2TTfgOmGbHQQEchrcpllaDAMMX
					dTDizw3t+vZ5SR32qJ8W7y6VXLgUqJgcdRxS
					Fou1pp+t5juRZSQ0LKgxMpZAgHorkzPvRf1b
					E9eBKrDSuLGagsQRwHeldFGFgsXtCbf07vVH
					zoKR8ynuG4/cAoY0JzMhCts+56U= )
			14400	NSEC	www.miek.nl. TXT RRSIG NSEC
			14400	RRSIG	NSEC 8 4 14400 (
					20160426031301 20160327031301 12051 miek.nl.
					BW6qo7kYe3Z+Y0ebaVTWTy1c3bpdf8WUEoXq
					WDQxLDEj2fFiuEBDaSN5lTWRg3wj8kZmr6Uk
					LvX0P29lbATFarIgkyiAdbOEdaf88nMfqBW8
					z2T5xrPQcN0F13uehmv395yAJs4tebRxErMl
					KdkVF0dskaDvw8Wo3YgjHUf6TXM= )
www.miek.nl.		1800	IN CNAME a.miek.nl.
			1800	RRSIG	CNAME 8 3 1800 (
					20160426031301 20160327031301 12051 miek.nl.
					MiQQh2lScoNiNVZmMJaypS+wDL2Lar4Zw1zF
					Uo4tL16BfQOt7yl8gXdAH2JMFqoKAoIdM2K6
					XwFOwKTOGSW0oNCOcaE7ts+1Z1U0H3O2tHfq
					FAzfg1s9pQ5zxk8J/bJgkVIkw2/cyB0y1/PK
					EmIqvChBSb4NchTuMCSqo63LJM8= )
			14400	NSEC	miek.nl. CNAME RRSIG NSEC
			14400	RRSIG	NSEC 8 3 14400 (
					20160426031301 20160327031301 12051 miek.nl.
					OPPZ8iaUPrVKEP4cqeCiiv1WLRAY30GRIhc/
					me0gBwFkbmTEnvB+rUp831OJZDZBNKv4QdZj
					Uyc26wKUOQeUyMJqv4IRDgxH7nq9GB5JRjYZ
					IVxtGD1aqWLXz+8aMaf9ARJjtYUd3K4lt8Wz
					LbJSo5Wdq7GOWqhgkY5n3XD0/FA= )`

	router := New()
	router.HandleZone(strings.NewReader(s), "miek.nl.", "stdin")

	tc := testCase{
		Qname: "b.miek.nl.", Qtype: dns.TypeA, Do: true,
		Rcode: dns.RcodeNameError,
		Ns: []dns.RR{
			nsec("archive.miek.nl.	14400	IN	NSEC	go.dns.miek.nl. CNAME RRSIG NSEC"),
			rrsig("archive.miek.nl.	14400	IN	RRSIG	NSEC 8 3 14400 20160426031301 20160327031301 12051 miek.nl. jEpx8lcp4do5fWXg="),
			nsec("miek.nl.	14400	IN	NSEC	a.miek.nl. A NS SOA MX AAAA RRSIG NSEC DNSKEY"),
			rrsig("miek.nl.	14400	IN	RRSIG	NSEC 8 2 14400 20160426031301 20160327031301 12051 miek.nl. mFfc3r/9PSC1H6oSpdC"),
			rrsig("miek.nl.	1800	IN	RRSIG	SOA 8 2 1800 20160426031301 20160327031301 12051 miek.nl. FIrzy07acBbtyQczy1dc="),
			soa("miek.nl.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"),
		},
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		resp := new(responseWriter)
		req := &Request{Msg: tc.Msg()}
		ChainHandler(router, DefaultScheme...).ServeDNS(resp, req)
	}
}

func TestLookupGlue(t *testing.T) {
	const s = `
; File written on Tue Dec 13 04:13:01 2016
; dnssec_signzone version 9.10.3-P4-Debian
atoom.net.		1800	IN SOA	linode.atoom.net. miek.miek.nl. (
					1481602381 ; serial
					14400      ; refresh (4 hours)
					3600       ; retry (1 hour)
					604800     ; expire (1 week)
					14400      ; minimum (4 hours)
					)
			1800	RRSIG	SOA 8 2 1800 (
					20170112031301 20161213031301 53289 atoom.net.
					GZ30uFuGATKzwHXgpEwK70qjdXSAqmbB5d4z
					e7WTibvJDPLa1ptZBI7Zuod2KMOkT1ocSvhL
					U7makhdv0BQx+5RSaP25mAmPIzfU7/T7R+DJ
					5q1GLlDSvOprfyMUlwOgZKZinesSdUa9gRmu
					8E+XnPNJ/jcTrGzzaDjn1/irrM0= )
			1800	NS	omval.tednet.nl.
			1800	NS	linode.atoom.net.
			1800	NS	ns-ext.nlnetlabs.nl.
			1800	RRSIG	NS 8 2 1800 (
					20170112031301 20161213031301 53289 atoom.net.
					D8Sd9JpXIOxOrUF5Hi1ASutyQwP7JNu8XZxA
					rse86A6L01O8H8sCNib2VEoJjHuZ/dDEogng
					OgmfqeFy04cpSX19GAk3bkx8Lr6aEat3nqIC
					XA/xsCCfXy0NKZpI05zntHPbbP5tF/NvpE7n
					0+oLtlHSPEg1ZnEgwNoLe+G1jlw= )
			1800	A	176.58.119.54
			1800	RRSIG	A 8 2 1800 (
					20170112031301 20161213031301 53289 atoom.net.
					mrjiUFNCqDgCW8TuhjzcMh0V841uC224QvwH
					0+OvYhcve9twbX3Y12PSFmz77Xz3Jg9WAj4I
					qhh3iHUac4dzUXyC702DT62yMF/9CMUO0+Ee
					b6wRtvPHr2Tt0i/xV/BTbArInIvurXJrvKvo
					LsZHOfsg7dZs6Mvdpe/CgwRExpk= )
			1800	AAAA	2a01:7e00::f03c:91ff:fe79:234c
			1800	RRSIG	AAAA 8 2 1800 (
					20170112031301 20161213031301 53289 atoom.net.
					EkMxX2vUaP4h0qbWlHaT4yNhm8MrPMZTn/3R
					zNw+i3oF2cLMWKh6GCfuIX/x5ID706o8kfum
					bxTYwuTe1LJ+GoZHWEiH8VCa1laTlh8l3qSi
					PZKU8339rr5cCYluk6p9PbAuRkYYOEruNg42
					wPOx46dsAlvp2XpOaOeJtU64QGQ= )
			14400	NSEC	deb.atoom.net. A NS SOA AAAA RRSIG NSEC DNSKEY
			14400	RRSIG	NSEC 8 2 14400 (
					20170112031301 20161213031301 53289 atoom.net.
					P7Stx7lqRKl8tbTAAaJ0W6UhgJwZz3cjpM8z
					eplbhXEVohKtyJ9xgptKt1vreH6lkhzciar5
					EB9Nj0VOmcthiht/+As8aEKmf8UlcJ2EbLII
					NT7NUaasxsrLE2rjjX5mEtzOZ1uQAGiU8Hnk
					XdGweTgIVFuiCcMCgaKpC2TRrMw= )
			1800	DNSKEY	256 3 8 (
					AwEAAeDZTH9YT9qLMPlq4VrxX7H3GbWcqCrC
					tXc9RT/hf96GN+ttnnEQVaJY8Gbly3IZpYQW
					MwaCi0t30UULXE3s9FUQtl4AMbplyiz9EF8L
					/XoBS1yhGm5WV5u608ihoPaRkYNyVV3egb5Y
					hA5EXWy2vfsa1XWPpxvSAhlqM0YENtP3
					) ; ZSK; alg = RSASHA256; key id = 53289
			1800	DNSKEY	257 3 8 (
					AwEAAepN7Vo8enDCruVduVlGxTDIv7QG0wJQ
					fTL1hMy4k0Yf/7dXzrn5bZT4ytBvH1hoBImH
					mtTrQo6DQlBBVXDJXTyQjQozaHpN1HhTJJTz
					IXl8UrdbkLWvz6QSeJPmBBYQRAqylUA2KE29
					nxyiNboheDLiIWyQ7Q/Op7lYaKMdb555kQAs
					b/XT4Tb3/3BhAjcofNofNBjDjPq2i8pAo8HU
					5mW5/Pl+ZT/S0aqQPnCkHk/iofSRu3ZdBzkH
					54eoC+BdyXb7gTbPGRr+1gMbf/rzhRiZ4vnX
					NoEzGAXmorKzJHANNb6KQ/932V9UDHm9wbln
					6y3s7IBvsMX5KF8vo81Stkc=
					) ; KSK; alg = RSASHA256; key id = 19114
			1800	RRSIG	DNSKEY 8 2 1800 (
					20170112031301 20161213031301 19114 atoom.net.
					IEjViubKdef8RWB5bcnirqVcqDk16irkywJZ
					sBjMyNs03/a+sl0UHEGAB7qCC+Rn+RDaM5It
					WF+Gha6BwRIN9NuSg3BwB2h1nJtHw61pMVU9
					2j9Q3pq7X1xoTBAcwY95t5a1xlw0iTCaLu1L
					Iu/PbVp1gj1o8BF/PiYilvZJGUjaTgsi+YNi
					2kiWpp6afO78/W4nfVx+lQBmpyfX1lwL5PEC
					9f5PMbzRmOapvUBc2XdddGywLdmlNsLHimGV
					t7kkHZHOWQR1TvvMbU3dsC0bFCrBVGDhEuxC
					hATR+X5YV0AyDSyrew7fOGJKrapwMWS3yRLr
					FAt0Vcxno5lwQImbCQ== )
			1800	RRSIG	DNSKEY 8 2 1800 (
					20170112031301 20161213031301 53289 atoom.net.
					sSxdgPT+gFZPN0ot6lZRGqOwvONUEsg0uEbf
					kh19JlWHu/qvq5HOOK2VOW/UnswpVmtpFk0W
					z/jiCNHifjpCCVn5tfCMZDLGekmPOjdobw24
					swBuGjnn0NHvxHoN6S+mb+AR6V/dLjquNUda
					yzBc2Ua+XtQ7SCLKIvEhcNg9H3o= )
deb.atoom.net.		1800	IN A	176.58.119.54
			1800	RRSIG	A 8 3 1800 (
					20170112031301 20161213031301 53289 atoom.net.
					ZW7jm/VDa/I9DxWlE7Cm+HHymiVv4Wk5UGYI
					Uf/g0EfxLCBR6SwL5QKuV1z7xoWKaiNqqrmc
					gg35xgskKyS8QHgCCODhDzcIKe+MSsBXbY04
					AtrC5dV3JJQoA65Ng/48hwcyghAjXKrA2Yyq
					GXf2DSvWeIV9Jmk0CsOELP24dpk= )
			1800	TXT	"v=spf1 a ip6:2a01:7e00::f03c:91ff:fe79:234c ~all"
			1800	RRSIG	TXT 8 3 1800 (
					20170112031301 20161213031301 53289 atoom.net.
					fpvVJ+Z6tzSd9yETn/PhLSCRISwRD1c3ET80
					8twnx3XfAPQfV2R8dw7pz8Vw4TSxvf19bAZc
					PWRjW682gb7gAxoJshCXBYabMfqExrBc9V1S
					ezwm3D93xNMyegxzHx2b/H8qp3ZWdsMLTvvN
					Azu7P4iyO+WRWT0R7bJGrdTwRz8= )
			1800	AAAA	2a01:7e00::f03c:91ff:fe79:234c
			1800	RRSIG	AAAA 8 3 1800 (
					20170112031301 20161213031301 53289 atoom.net.
					aaPF6NqXfWamzi+xUDVeYa7StJUVM1tDsL34
					w5uozFRZ0f4K/Z88Kk5CgztxmtpNNKGdLWa0
					iryUJsbVWAbSQfrZNkNckBtczMNxGgjqn97A
					2//F6ajH/qrR3dWcCm+VJMgu3UPqAxLiCaYO
					GQUx6Y8JA1VIM/RJAM6BhgNxjD0= )
			14400	NSEC	lafhart.atoom.net. A TXT AAAA RRSIG NSEC
			14400	RRSIG	NSEC 8 3 14400 (
					20170112031301 20161213031301 53289 atoom.net.
					1Llad64NDWcz8CyBu2TsyANrJ9Tpfm5257sY
					FPYF579p3c9Imwp9kYEO1zMEKgNoXBN/sQnd
					YCugq3r2GAI6bfJj8sV5bt6GKuZcGHMESug4
					uh2gU0NDcCA4GPdBYGdusePwV0RNpcRnVCFA
					fsACp+22j3uwRUbCh0re0ufbAs4= )
lafhart.atoom.net.	1800	IN A	178.79.160.171
			1800	RRSIG	A 8 3 1800 (
					20170112031301 20161213031301 53289 atoom.net.
					fruP6cvMVICXEV8NcheS73NWLCEKlO1FgW6B
					35D2GhtfYZe+M23V5YBRtlVCCrAdS0etdCOf
					xH9yt3u2kVvDXuMRiQr1zJPRDEq3cScYumpd
					bOO8cjHiCic5lEcRVWNNHXyGtpqTvrp9CxOu
					IQw1WgAlZyKj43zGg3WZi6OTKLg= )
			14400	NSEC	linode.atoom.net. A RRSIG NSEC
			14400	RRSIG	NSEC 8 3 14400 (
					20170112031301 20161213031301 53289 atoom.net.
					2AUWXbScL0jIJ7G6UsJAlUs+bgSprZ1zY6v/
					iVB5BAYwZD6pPky7LZdzvPEHh0aNLGIFbbU8
					SDJI7u/e4RUTlE+8yyjl6obZNfNKyJFqE5xN
					1BJ8sjFrVn6KaHIDKEOZunNb1MlMfCRkLg9O
					94zg04XEgVUfaYCPxvLs3fCEgzw= )
voordeur.atoom.net.	1800	IN A	77.249.87.46
			1800	RRSIG	A 8 3 1800 (
					20170112031301 20161213031301 53289 atoom.net.
					SzJz0NaKLRA/lW4CxgMHgeuQLp5QqFEjQv3I
					zfPtY4joQsZn8RN8RLECcpcPKjbC8Dj6mxIJ
					dd2vwhsCVlZKMNcZUOfpB7eGx1TR9HnzMkY9
					OdTt30a9+tktagrJEoy31vAhj1hJqLbSgvOa
					pRr1P4ZpQ53/qH8JX/LOmqfWTdg= )
			14400	NSEC	www.atoom.net. A RRSIG NSEC
			14400	RRSIG	NSEC 8 3 14400 (
					20170112031301 20161213031301 53289 atoom.net.
					CETJhUJy1rKjVj9wsW1549gth+/Z37//BI6S
					nxJ+2Oq63jEjlbznmyo5hvFW54DbVUod+cLo
					N9PdlNQDr1XsRBgWhkKW37RkuoRVEPwqRykv
					xzn9i7CgYKAAHFyWMGihBLkV9ByPp8GDR8Zr
					DEkrG3ErDlBcwi3FqGZFsSOW2xg= )
www.atoom.net.		1800	IN CNAME deb.atoom.net.
			1800	RRSIG	CNAME 8 3 1800 (
					20170112031301 20161213031301 53289 atoom.net.
					1lhG6iTtbeesBCVOrA8a7+V2gogCuXzKgSi8
					6K0Pzq2CwqTScdNcZvcDOIbLq45Am5p09PIj
					lXnd2fw6WAxphwvRhmwCve3uTZMUt5STw7oi
					0rED7GMuFUSC/BX0XVly7NET3ECa1vaK6RhO
					hDSsKPWFI7to4d1z6tQ9j9Kvm4Y= )
			14400	NSEC	atoom.net. CNAME RRSIG NSEC
			14400	RRSIG	NSEC 8 3 14400 (
					20170112031301 20161213031301 53289 atoom.net.
					CC4yCYP1q75/gTmPz+mVM6Lam2foPP5oTccY
					RtROuTkgbt8DtAoPe304vmNazWBlGidnWJeD
					YyAAe3znIHP0CgrxjD/hRL9FUzMnVrvB3mnx
					4W13wP1rE97RqJxV1kk22Wl3uCkVGy7LCjb0
					JLFvzCe2fuMe7YcTzI+t1rioTP0= )
linode.atoom.net.	1800	IN A	176.58.119.54
			1800	RRSIG	A 8 3 1800 (
					20170112031301 20161213031301 53289 atoom.net.
					Z4Ka4OLDha4eQNWs3GtUd1Cumr48RUnH523I
					nZzGXtpQNou70qsm5Jt8n/HmsZ4L5DoxomRz
					rgZTGnrqj43+A16UUGfVEk6SfUUHOgxgspQW
					zoaqk5/5mQO1ROsLKY8RqaRqzvbToHvqeZEh
					VkTPVA02JK9UFlKqoyxj72CLvkI= )
			1800	AAAA	2a01:7e00::f03c:91ff:fe79:234c
			1800	RRSIG	AAAA 8 3 1800 (
					20170112031301 20161213031301 53289 atoom.net.
					l+9Qce/EQyKrTJVKLv7iatjuCO285ckd5Oie
					P2LzWVsL4tW04oHzieKZwIuNBRE+px8g5qrT
					LIK2TikCGL1xHAd7CT7gbCtDcZ7jHmSTmMTJ
					405nOV3G3xWelreLI5Fn5ck8noEsF64kiw1y
					XfkyQn2B914zFH/okG2fzJ1qolQ= )
			14400	NSEC	voordeur.atoom.net. A AAAA RRSIG NSEC
			14400	RRSIG	NSEC 8 3 14400 (
					20170112031301 20161213031301 53289 atoom.net.
					Owzmz7QrVL2Gw2njEsUVEknMl2amx1HG9X3K
					tO+Ihyy4tApiUFxUjAu3P/30QdqbB85h7s//
					ipwX/AmQJNoxTScR3nHt9qDqJ044DPmiuh0l
					NuIjguyZRANApmKCTA6AoxXIUqToIIjfVzi/
					PxXE6T3YIPlK7Bxgv1lcCBJ1fmE= )`

	const atoom = "atoom.net."

	var dnsTestCases = []testCase{
		{
			Qname: atoom, Qtype: dns.TypeNS, Do: true,
			Answer: []dns.RR{
				ns("atoom.net.		1800	IN	NS	linode.atoom.net."),
				ns("atoom.net.		1800	IN	NS	ns-ext.nlnetlabs.nl."),
				ns("atoom.net.		1800	IN	NS	omval.tednet.nl."),
				rrsig("atoom.net.		1800	IN	RRSIG	NS 8 2 1800 20170112031301 20161213031301 53289 atoom.net. DLe+G1 jlw="),
			},
			Extra: []dns.RR{
				opt(4096, true),
				a("linode.atoom.net.	1800	IN	A	176.58.119.54"),
				aaaa("linode.atoom.net.	1800	IN	AAAA	2a01:7e00::f03c:91ff:fe79:234c"),
				rrsig("linode.atoom.net.	1800	IN	RRSIG	A 8 3 1800 20170112031301 20161213031301 53289 atoom.net. Z4Ka4OLDoyxj72CL vkI="),
				rrsig("linode.atoom.net.	1800	IN	RRSIG	AAAA 8 3 1800 20170112031301 20161213031301 53289 atoom.net. l+9Qc914zFH/okG2fzJ1q olQ="),
			},
		},
	}

	router := New()
	router.HandleZone(strings.NewReader(s), atoom, "stdin")

	for _, tc := range dnsTestCases {
		resp := new(responseWriter)
		req := &Request{Msg: tc.Msg()}
		ChainHandler(router, DefaultScheme...).ServeDNS(resp, req)
		sortAndCheck(t, &resp.msg, tc)
	}
}

func TestLookupEnt(t *testing.T) {
	const s = `; File written on Sat Apr  2 16:43:11 2016
; dnssec_signzone version 9.10.3-P4-Ubuntu
miek.nl.		1800	IN SOA	linode.atoom.net. miek.miek.nl. (
					1282630057 ; serial
					14400      ; refresh (4 hours)
					3600       ; retry (1 hour)
					604800     ; expire (1 week)
					14400      ; minimum (4 hours)
					)
			1800	RRSIG	SOA 8 2 1800 (
					20160502144311 20160402144311 12051 miek.nl.
					KegoBxA3Tbrhlc4cEdkRiteIkOfsqD4oCLLM
					ISJ5bChWy00LGHUlAnHVu5Ti96hUjVNmGSxa
					xtGSuAAMFCr52W8pAB8LBIlu9B6QZUPHMccr
					SuzxAX3ioawk2uTjm+k8AGPT4RoQdXemGLAp
					zJTASolTVmeMTh5J0sZTZJrtvZ0= )
			1800	NS	linode.atoom.net.
			1800	RRSIG	NS 8 2 1800 (
					20160502144311 20160402144311 12051 miek.nl.
					m0cOHL6Rre/0jZPXe+0IUjs/8AFASRCvDbSx
					ZQsRDSlZgS6RoMP3OC77cnrKDVlfZ2Vhq3Ce
					nYPoGe0/atB92XXsilmstx4HTSU64gsV9iLN
					Xkzk36617t7zGOl/qumqfaUXeA9tihItzEim
					6SGnufVZI4o8xeyaVCNDDuN0bvY= )
			14400	NSEC	a.miek.nl. NS SOA RRSIG NSEC DNSKEY
			14400	RRSIG	NSEC 8 2 14400 (
					20160502144311 20160402144311 12051 miek.nl.
					BCWVgwxWrs4tBjS9QXKkftCUbiLi40NyH1yA
					nbFy1wCKQ2jDH00810+ia4b66QrjlAKgxE9z
					9U7MKSMV86sNkyAtlCi+2OnjtWF6sxPdJO7k
					CHeg46XBjrQuiJRY8CneQX56+IEPdufLeqPR
					l+ocBQ2UkGhXmQdWp3CFDn2/eqU= )
			1800	DNSKEY	256 3 8 (
					AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6
					E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5EC
					IoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb
					2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXH
					Py7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz
					) ; ZSK; alg = RSASHA256; key id = 12051
			1800	DNSKEY	257 3 8 (
					AwEAAcWdjBl4W4wh/hPxMDcBytmNCvEngIgB
					9Ut3C2+QI0oVz78/WK9KPoQF7B74JQ/mjO4f
					vIncBmPp6mFNxs9/WQX0IXf7oKviEVOXLjct
					R4D1KQLX0wprvtUIsQFIGdXaO6suTT5eDbSd
					6tTwu5xIkGkDmQhhH8OQydoEuCwV245ZwF/8
					AIsqBYDNQtQ6zhd6jDC+uZJXg/9LuPOxFHbi
					MTjp6j3CCW0kHbfM/YHZErWWtjPj3U3Z7knQ
					SIm5PO5FRKBEYDdr5UxWJ/1/20SrzI3iztvP
					wHDsA2rdHm/4YRzq7CvG4N0t9ac/T0a0Sxba
					/BUX2UVPWaIVBdTRBtgHi0s=
					) ; KSK; alg = RSASHA256; key id = 33694
			1800	RRSIG	DNSKEY 8 2 1800 (
					20160502144311 20160402144311 12051 miek.nl.
					YNpi1jRDQKpnsQEjIjxqy+kJGaYnV16e8Iug
					40c82y4pee7kIojFUllSKP44qiJpCArxF557
					tfjfwBd6c4hkqCScGPZXJ06LMyG4u//rhVMh
					4hyKcxzQFKxmrFlj3oQGksCI8lxGX6RxiZuR
					qv2ol2lUWrqetpAL+Zzwt71884E= )
			1800	RRSIG	DNSKEY 8 2 1800 (
					20160502144311 20160402144311 33694 miek.nl.
					jKpLDEeyadgM0wDgzEk6sBBdWr2/aCrkAOU/
					w6dYIafN98f21oIYQfscV1gc7CTsA0vwzzUu
					x0QgwxoNLMvSxxjOiW/2MzF8eozczImeCWbl
					ad/pVCYH6Jn5UBrZ5RCWMVcs2RP5KDXWeXKs
					jEN/0EmQg5qNd4zqtlPIQinA9I1HquJAnS56
					pFvYyGIbZmGEbhR18sXVBeTWYr+zOMHn2quX
					0kkrx2udz+sPg7i4yRsLdhw138gPRy1qvbaC
					8ELs1xo1mC9pTlDOhz24Q3iXpVAU1lXLYOh9
					nUP1/4UvZEYXHBUQk/XPRciojniWjAF825x3
					QoSivMHblBwRdAKJSg== )
a.miek.nl.		1800	IN A	127.0.0.1
			1800	RRSIG	A 8 3 1800 (
					20160502144311 20160402144311 12051 miek.nl.
					lUOYdSxScjyYz+Ebc+nb6iTNgCohqj7K+Dat
					97KE7haV2nP3LxdYuDCJYZpeyhsXDLHd4bFI
					bInYPwJiC6DUCxPCuCWy0KYlZOWW8KCLX3Ia
					BOPQbvIwLsJhnX+/tyMD9mXortoqATO79/6p
					nNxvFeM8pFDwaih17fXMuFR/BsI= )
			14400	NSEC	a.b.c.miek.nl. A RRSIG NSEC
			14400	RRSIG	NSEC 8 3 14400 (
					20160502144311 20160402144311 12051 miek.nl.
					d5XZEy6SUp+TPRJQED+0R65zf2Yeo/1dlEA2
					jYYvkXGSHXke4sg9nH8U3nr1rLcuqA1DsQgH
					uMIjdENvXuZ+WCSwvIbhC+JEI6AyQ6Gfaf/D
					I3mfu60C730IRByTrKM5C2rt11lwRQlbdaUY
					h23/nn/q98ZKUlzqhAfkLI9pQPc= )
a.b.c.miek.nl.		1800	IN A	127.0.0.1
			1800	RRSIG	A 8 5 1800 (
					20160502144311 20160402144311 12051 miek.nl.
					FwgU5+fFD4hEebco3gvKQt3PXfY+dcOJr8dl
					Ky4WLsONIdhP+4e9oprPisSLxImErY21BcrW
					xzu1IZrYDsS8XBVV44lBx5WXEKvAOrUcut/S
					OWhFZW7ncdIQCp32ZBIatiLRJEqXUjx+guHs
					noFLiHix35wJWsRKwjGLIhH1fbs= )
			14400	NSEC	miek.nl. A RRSIG NSEC
			14400	RRSIG	NSEC 8 5 14400 (
					20160502144311 20160402144311 12051 miek.nl.
					lXgOqm9/jRRYvaG5jC1CDvTtGYxMroTzf4t4
					jeYGb60+qI0q9sHQKfAJvoQ5o8o1qfR7OuiF
					f544ipYT9eTcJRyGAOoJ37yMie7ZIoVJ91tB
					r8YdzZ9Q6x3v1cbwTaQiacwhPZhGYOw63qIs
					q5IQErIPos2sNk+y9D8BEce2DO4= )`

	var dnsTestCases = []testCase{
		{
			Qname: "b.c.miek.nl.", Qtype: dns.TypeA,
			Ns: []dns.RR{
				soa("miek.nl.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"),
			},
		},
		{
			Qname: "b.c.miek.nl.", Qtype: dns.TypeA, Do: true,
			Ns: []dns.RR{
				nsec("a.miek.nl.	14400	IN	NSEC	a.b.c.miek.nl. A RRSIG NSEC"),
				rrsig("a.miek.nl.	14400	IN	RRSIG	NSEC 8 3 14400 20160502144311 20160402144311 12051 miek.nl. d5XZEy6SUpq98ZKUlzqhAfkLI9pQPc="),
				rrsig("miek.nl.	1800	IN	RRSIG	SOA 8 2 1800 20160502144311 20160402144311 12051 miek.nl. KegoBxA3Tbrhlc4cEdkRiteIkOfsq"),
				soa("miek.nl.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"),
			},
			Extra: []dns.RR{opt(4096, true)},
		},
	}

	router := New()
	router.HandleZone(strings.NewReader(s), "miek.nl.", "stdin")

	for _, tc := range dnsTestCases {
		resp := new(responseWriter)
		req := &Request{Msg: tc.Msg()}
		ChainHandler(router, DefaultScheme...).ServeDNS(resp, req)
		sortAndCheck(t, &resp.msg, tc)
	}
}

func TestLookupDS(t *testing.T) {
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

delegated	IN	NS      a.delegated
			IN	NS      ns-ext.nlnetlabs.nl.

a.delegated     IN      TXT     "obscured"
				IN      A       139.162.196.78
				IN      AAAA    2a01:7e00::f03c:91ff:fef1:6735

a               IN      A       139.162.196.78
				IN      AAAA    2a01:7e00::f03c:91ff:fef1:6735
www             IN      CNAME   a
archive         IN      CNAME   a`

	var dnsTestCases = []testCase{
		{
			Qname: "a.delegated.miek.nl.", Qtype: dns.TypeDS,
			Ns: []dns.RR{
				ns("delegated.miek.nl.	1800	IN	NS	a.delegated.miek.nl."),
				ns("delegated.miek.nl.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
			},
			Extra: []dns.RR{
				a("a.delegated.miek.nl. 1800 IN A 139.162.196.78"),
				aaaa("a.delegated.miek.nl. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735"),
			},
		},
		{
			Qname: "_udp.delegated.miek.nl.", Qtype: dns.TypeDS,
			Ns: []dns.RR{
				ns("delegated.miek.nl.	1800	IN	NS	a.delegated.miek.nl."),
				ns("delegated.miek.nl.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
			},
			Extra: []dns.RR{
				a("a.delegated.miek.nl. 1800 IN A 139.162.196.78"),
				aaaa("a.delegated.miek.nl. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735"),
			},
		},
		{
			// This works *here* because we skip the server routing for DS in core/dnsserver/server.go
			Qname: "_udp.miek.nl.", Qtype: dns.TypeDS,
			Rcode: dns.RcodeNameError,
			Ns: []dns.RR{
				soa("miek.nl.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"),
			},
		},
		{
			Qname: "miek.nl.", Qtype: dns.TypeDS,
			Ns: []dns.RR{
				soa("miek.nl.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"),
			},
		},
	}

	router := New()
	router.HandleZone(strings.NewReader(s), "miek.nl.", "stdin")

	for _, tc := range dnsTestCases {
		resp := new(responseWriter)
		req := &Request{Msg: tc.Msg()}
		ChainHandler(router, DefaultScheme...).ServeDNS(resp, req)
		sortAndCheck(t, &resp.msg, tc)
	}
}

func TestLookupDelegation(t *testing.T) {
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

delegated	IN	NS      a.delegated
			IN	NS      ns-ext.nlnetlabs.nl.

a.delegated     IN      TXT     "obscured"
                IN      A       139.162.196.78
                IN      AAAA    2a01:7e00::f03c:91ff:fef1:6735

a               IN      A       139.162.196.78
                IN      AAAA    2a01:7e00::f03c:91ff:fef1:6735
www             IN      CNAME   a
archive         IN      CNAME   a`

	var miekAuth = []dns.RR{
		ns("miek.nl.	1800	IN	NS	ext.ns.whyscream.net."),
		ns("miek.nl.	1800	IN	NS	linode.atoom.net."),
		ns("miek.nl.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
		ns("miek.nl.	1800	IN	NS	omval.tednet.nl."),
	}

	var dnsTestCases = []testCase{
		{
			Qname: "a.delegated.miek.nl.", Qtype: dns.TypeTXT,
			Ns: []dns.RR{
				ns("delegated.miek.nl.	1800	IN	NS	a.delegated.miek.nl."),
				ns("delegated.miek.nl.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
			},
			Extra: []dns.RR{
				a("a.delegated.miek.nl. 1800 IN A 139.162.196.78"),
				aaaa("a.delegated.miek.nl. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735"),
			},
		},
		{
			Qname: "delegated.miek.nl.", Qtype: dns.TypeNS,
			Ns: []dns.RR{
				ns("delegated.miek.nl.	1800	IN	NS	a.delegated.miek.nl."),
				ns("delegated.miek.nl.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
			},
			Extra: []dns.RR{
				a("a.delegated.miek.nl. 1800 IN A 139.162.196.78"),
				aaaa("a.delegated.miek.nl. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735"),
			},
		},
		{
			Qname: "foo.delegated.miek.nl.", Qtype: dns.TypeA,
			Ns: []dns.RR{
				ns("delegated.miek.nl.	1800	IN	NS	a.delegated.miek.nl."),
				ns("delegated.miek.nl.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
			},
			Extra: []dns.RR{
				a("a.delegated.miek.nl. 1800 IN A 139.162.196.78"),
				aaaa("a.delegated.miek.nl. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735"),
			},
		},
		{
			Qname: "foo.delegated.miek.nl.", Qtype: dns.TypeTXT,
			Ns: []dns.RR{
				ns("delegated.miek.nl.	1800	IN	NS	a.delegated.miek.nl."),
				ns("delegated.miek.nl.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
			},
			Extra: []dns.RR{
				a("a.delegated.miek.nl. 1800 IN A 139.162.196.78"),
				aaaa("a.delegated.miek.nl. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735"),
			},
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
			Ns: []dns.RR{
				soa("miek.nl.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"),
			},
		},
	}

	router := New()
	router.HandleZone(strings.NewReader(s), "miek.nl.", "stdin")

	for _, tc := range dnsTestCases {
		resp := new(responseWriter)
		req := &Request{Msg: tc.Msg()}
		ChainHandler(router, DefaultScheme...).ServeDNS(resp, req)
		sortAndCheck(t, &resp.msg, tc)
	}
}

func TestLookupSecureDelegation(t *testing.T) {
	const s = `
example.org.		1800	IN SOA	a.iana-servers.net. devnull.example.org. (
					1282630057 ; serial
					14400      ; refresh (4 hours)
					3600       ; retry (1 hour)
					604800     ; expire (1 week)
					14400      ; minimum (4 hours)
					)
			1800	RRSIG	SOA 13 2 1800 (
					20161129153240 20161030153240 49035 example.org.
					GVnMpFmN+6PDdgCtlYDEYBsnBNDgYmEJNvos
					Bk9+PNTPNWNst+BXCpDadTeqRwrr1RHEAQ7j
					YWzNwqn81pN+IA== )
			1800	NS	a.iana-servers.net.
			1800	NS	b.iana-servers.net.
			1800	RRSIG	NS 13 2 1800 (
					20161129153240 20161030153240 49035 example.org.
					llrHoIuwjnbo28LOt4p5zWAs98XGqrXicKVI
					Qxyaf/ORM8boJvW2XrKr3nj6Y8FKMhzd287D
					5PBzVCL6MZyjQg== )
			14400	NSEC	a.example.org. NS SOA RRSIG NSEC DNSKEY
			14400	RRSIG	NSEC 13 2 14400 (
					20161129153240 20161030153240 49035 example.org.
					BQROf1swrmYi3GqpP5M/h5vTB8jmJ/RFnlaX
					7fjxvV7aMvXCsr3ekWeB2S7L6wWFihDYcKJg
					9BxVPqxzBKeaqg== )
			1800	DNSKEY	256 3 13 (
					UNTqlHbC51EbXuY0rshW19Iz8SkCuGVS+L0e
					bQj53dvtNlaKfWmtTauC797FoyVLbQwoMy/P
					G68SXgLCx8g+9g==
					) ; ZSK; alg = ECDSAP256SHA256; key id = 49035
			1800	RRSIG	DNSKEY 13 2 1800 (
					20161129153240 20161030153240 49035 example.org.
					LnLHyqYJaCMOt7EHB4GZxzAzWLwEGCTFiEhC
					jj1X1VuQSjJcN42Zd3yF+jihSW6huknrig0Z
					Mqv0FM6mJ/qPKg== )
a.delegated.example.org. 1800	IN A	139.162.196.78
			1800	TXT	"obscured"
			1800	AAAA	2a01:7e00::f03c:91ff:fef1:6735
archive.example.org.	1800	IN CNAME a.example.org.
			1800	RRSIG	CNAME 13 3 1800 (
					20161129153240 20161030153240 49035 example.org.
					SDFW1z/PN9knzH8BwBvmWK0qdIwMVtGrMgRw
					7lgy4utRrdrRdCSLZy3xpkmkh1wehuGc4R0S
					05Z3DPhB0Fg5BA== )
			14400	NSEC	delegated.example.org. CNAME RRSIG NSEC
			14400	RRSIG	NSEC 13 3 14400 (
					20161129153240 20161030153240 49035 example.org.
					DQqLSVNl8F6v1K09wRU6/M6hbHy2VUddnOwn
					JusJjMlrAOmoOctCZ/N/BwqCXXBA+d9yFGdH
					knYumXp+BVPBAQ== )
www.example.org.	1800	IN CNAME a.example.org.
			1800	RRSIG	CNAME 13 3 1800 (
					20161129153240 20161030153240 49035 example.org.
					adzujOxCV0uBV4OayPGfR11iWBLiiSAnZB1R
					slmhBFaDKOKSNYijGtiVPeaF+EuZs63pzd4y
					6Nm2Iq9cQhAwAA== )
			14400	NSEC	example.org. CNAME RRSIG NSEC
			14400	RRSIG	NSEC 13 3 14400 (
					20161129153240 20161030153240 49035 example.org.
					jy3f96GZGBaRuQQjuqsoP1YN8ObZF37o+WkV
					PL7TruzI7iNl0AjrUDy9FplP8Mqk/HWyvlPe
					N3cU+W8NYlfDDQ== )
a.example.org.		1800	IN A	139.162.196.78
			1800	RRSIG	A 13 3 1800 (
					20161129153240 20161030153240 49035 example.org.
					41jFz0Dr8tZBN4Kv25S5dD4vTmviFiLx7xSA
					qMIuLFm0qibKL07perKpxqgLqM0H1wreT4xz
					I9Y4Dgp1nsOuMA== )
			1800	AAAA	2a01:7e00::f03c:91ff:fef1:6735
			1800	RRSIG	AAAA 13 3 1800 (
					20161129153240 20161030153240 49035 example.org.
					brHizDxYCxCHrSKIu+J+XQbodRcb7KNRdN4q
					VOWw8wHqeBsFNRzvFF6jwPQYphGP7kZh1KAb
					VuY5ZVVhM2kHjw== )
			14400	NSEC	archive.example.org. A AAAA RRSIG NSEC
			14400	RRSIG	NSEC 13 3 14400 (
					20161129153240 20161030153240 49035 example.org.
					zIenVlg5ScLr157EWigrTGUgrv7W/1s49Fic
					i2k+OVjZfT50zw+q5X6DPKkzfAiUhIuqs53r
					hZUzZwV/1Wew9Q== )
delegated.example.org.	1800	IN NS	a.delegated.example.org.
			1800	IN NS	ns-ext.nlnetlabs.nl.
			1800	DS	10056 5 1 (
					EE72CABD1927759CDDA92A10DBF431504B9E
					1F13 )
			1800	DS	10056 5 2 (
					E4B05F87725FA86D9A64F1E53C3D0E625094
					6599DFE639C45955B0ED416CDDFA )
			1800	RRSIG	DS 13 3 1800 (
					20161129153240 20161030153240 49035 example.org.
					rlNNzcUmtbjLSl02ZzQGUbWX75yCUx0Mug1j
					HtKVqRq1hpPE2S3863tIWSlz+W9wz4o19OI4
					jbznKKqk+DGKog== )
			14400	NSEC	sub.example.org. NS DS RRSIG NSEC
			14400	RRSIG	NSEC 13 3 14400 (
					20161129153240 20161030153240 49035 example.org.
					lNQ5kRTB26yvZU5bFn84LYFCjwWTmBcRCDbD
					cqWZvCSw4LFOcqbz1/wJKIRjIXIqnWIrfIHe
					fZ9QD5xZsrPgUQ== )
sub.example.org.	1800	IN NS	sub1.example.net.
			1800	IN NS	sub2.example.net.
			14400	NSEC	www.example.org. NS RRSIG NSEC
			14400	RRSIG	NSEC 13 3 14400 (
					20161129153240 20161030153240 49035 example.org.
					VYjahdV+TTkA3RBdnUI0hwXDm6U5k/weeZZr
					ix1znORpOELbeLBMJW56cnaG+LGwOQfw9qqj
					bOuULDst84s4+g== )
`

	var dnsTestCases = []testCase{
		{
			Qname: "a.delegated.example.org.", Qtype: dns.TypeTXT,
			Do: true,
			Ns: []dns.RR{
				ds("delegated.example.org.	1800	IN	DS	10056 5 1 EE72CABD1927759CDDA92A10DBF431504B9E1F13"),
				ds("delegated.example.org.	1800	IN	DS	10056 5 2 E4B05F87725FA86D9A64F1E53C3D0E6250946599DFE639C45955B0ED416CDDFA"),
				ns("delegated.example.org.	1800	IN	NS	a.delegated.example.org."),
				ns("delegated.example.org.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
				rrsig("delegated.example.org.	1800	IN	RRSIG	DS 13 3 1800 20161129153240 20161030153240 49035 example.org. rlNNzcUmtbjLSl02ZzQGUbWX75yCUx0Mug1jHtKVqRq1hpPE2S3863tIWSlz+W9wz4o19OI4jbznKKqk+DGKog=="),
			},
			Extra: []dns.RR{
				opt(4096, true),
				a("a.delegated.example.org. 1800 IN A 139.162.196.78"),
				aaaa("a.delegated.example.org. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735"),
			},
		},
		{
			Qname: "delegated.example.org.", Qtype: dns.TypeNS,
			Do: true,
			Ns: []dns.RR{
				ds("delegated.example.org.	1800	IN	DS	10056 5 1 EE72CABD1927759CDDA92A10DBF431504B9E1F13"),
				ds("delegated.example.org.	1800	IN	DS	10056 5 2 E4B05F87725FA86D9A64F1E53C3D0E6250946599DFE639C45955B0ED416CDDFA"),
				ns("delegated.example.org.	1800	IN	NS	a.delegated.example.org."),
				ns("delegated.example.org.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
				rrsig("delegated.example.org.	1800	IN	RRSIG	DS 13 3 1800 20161129153240 20161030153240 49035 example.org. rlNNzcUmtbjLSl02ZzQGUbWX75yCUx0Mug1jHtKVqRq1hpPE2S3863tIWSlz+W9wz4o19OI4jbznKKqk+DGKog=="),
			},
			Extra: []dns.RR{
				opt(4096, true),
				a("a.delegated.example.org. 1800 IN A 139.162.196.78"),
				aaaa("a.delegated.example.org. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735"),
			},
		},
		{
			Qname: "foo.delegated.example.org.", Qtype: dns.TypeA,
			Do: true,
			Ns: []dns.RR{
				ds("delegated.example.org.	1800	IN	DS	10056 5 1 EE72CABD1927759CDDA92A10DBF431504B9E1F13"),
				ds("delegated.example.org.	1800	IN	DS	10056 5 2 E4B05F87725FA86D9A64F1E53C3D0E6250946599DFE639C45955B0ED416CDDFA"),
				ns("delegated.example.org.	1800	IN	NS	a.delegated.example.org."),
				ns("delegated.example.org.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
				rrsig("delegated.example.org.	1800	IN	RRSIG	DS 13 3 1800 20161129153240 20161030153240 49035 example.org. rlNNzcUmtbjLSl02ZzQGUbWX75yCUx0Mug1jHtKVqRq1hpPE2S3863tIWSlz+W9wz4o19OI4jbznKKqk+DGKog=="),
			},
			Extra: []dns.RR{
				opt(4096, true),
				a("a.delegated.example.org. 1800 IN A 139.162.196.78"),
				aaaa("a.delegated.example.org. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735"),
			},
		},
		{
			Qname: "foo.delegated.example.org.", Qtype: dns.TypeDS,
			Do: true,
			Ns: []dns.RR{
				ds("delegated.example.org.	1800	IN	DS	10056 5 1 EE72CABD1927759CDDA92A10DBF431504B9E1F13"),
				ds("delegated.example.org.	1800	IN	DS	10056 5 2 E4B05F87725FA86D9A64F1E53C3D0E6250946599DFE639C45955B0ED416CDDFA"),
				ns("delegated.example.org.	1800	IN	NS	a.delegated.example.org."),
				ns("delegated.example.org.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
				rrsig("delegated.example.org.	1800	IN	RRSIG	DS 13 3 1800 20161129153240 20161030153240 49035 example.org. rlNNzcUmtbjLSl02ZzQGUbWX75yCUx0Mug1jHtKVqRq1hpPE2S3863tIWSlz+W9wz4o19OI4jbznKKqk+DGKog=="),
			},
			Extra: []dns.RR{
				opt(4096, true),
				a("a.delegated.example.org. 1800 IN A 139.162.196.78"),
				aaaa("a.delegated.example.org. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735"),
			},
		},
		{
			Qname: "delegated.example.org.", Qtype: dns.TypeDS,
			Do: true,
			Answer: []dns.RR{
				ds("delegated.example.org.	1800	IN	DS	10056 5 1 EE72CABD1927759CDDA92A10DBF431504B9E1F13"),
				ds("delegated.example.org.	1800	IN	DS	10056 5 2 E4B05F87725FA86D9A64F1E53C3D0E6250946599DFE639C45955B0ED416CDDFA"),
				rrsig("delegated.example.org.	1800	IN	RRSIG	DS 13 3 1800 20161129153240 20161030153240 49035 example.org. rlNNzcUmtbjLSl02ZzQGUbWX75yCUx0Mug1jHtKVqRq1hpPE2S3863tIWSlz+W9wz4o19OI4jbznKKqk+DGKog=="),
			},
			Ns: []dns.RR{
				ns("example.org.	1800	IN	NS	a.iana-servers.net."),
				ns("example.org.	1800	IN	NS	b.iana-servers.net."),
				rrsig("example.org.	1800	IN	RRSIG	NS 13 2 1800 20161129153240 20161030153240 49035 example.org. llrHoIuw="),
			},
			Extra: []dns.RR{
				opt(4096, true),
			},
		},
	}

	router := New()
	router.HandleZone(strings.NewReader(s), "example.org.", "stdin")

	for _, tc := range dnsTestCases {
		resp := new(responseWriter)
		req := &Request{Msg: tc.Msg()}
		ChainHandler(router, DefaultScheme...).ServeDNS(resp, req)
		sortAndCheck(t, &resp.msg, tc)
	}
}

func TestLookupWildcard(t *testing.T) {
	const s = `
; File written on Tue Mar 29 21:02:24 2016
; dnssec_signzone version 9.10.3-P4-Ubuntu
dnssex.nl.		1800	IN SOA	linode.atoom.net. miek.miek.nl. (
					1459281744 ; serial
					14400      ; refresh (4 hours)
					3600       ; retry (1 hour)
					604800     ; expire (1 week)
					14400      ; minimum (4 hours)
					)
			1800	RRSIG	SOA 8 2 1800 (
					20160428190224 20160329190224 14460 dnssex.nl.
					CA/Y3m9hCOiKC/8ieSOv8SeP964BUdG/8MC3
					WtKljUosK9Z9bBGrVizDjjqgq++lyH8BZJcT
					aabAsERs4xj5PRtcxicwQXZACX5VYjXHQeZm
					CyytFU5wq2gcXSmvUH86zZzftx3RGPvn1aOo
					TlcvoC3iF8fYUCpROlUS0YR8Cdw= )
			1800	NS	omval.tednet.nl.
			1800	NS	linode.atoom.net.
			1800	NS	ns-ext.nlnetlabs.nl.
			1800	RRSIG	NS 8 2 1800 (
					20160428190224 20160329190224 14460 dnssex.nl.
					dLIeEvP86jj5nd3orv9bH7hTvkblF4Na0sbl
					k6fJA6ha+FPN1d6Pig3NNEEVQ/+wlOp/JTs2
					v07L7roEEUCbBprI8gMSld2gFDwNLW3DAB4M
					WD/oayYdAnumekcLzhgvWixTABjWAGRTGQsP
					sVDFXsGMf9TGGC9FEomgkCVeNC0= )
			1800	A	139.162.196.78
			1800	RRSIG	A 8 2 1800 (
					20160428190224 20160329190224 14460 dnssex.nl.
					LKJKLzPiSEDWOLAag2YpfD5EJCuDcEAJu+FZ
					Xy+4VyOv9YvRHCTL4vbrevOo5+XymY2RxU1q
					j+6leR/Fe7nlreSj2wzAAk2bIYn4m6r7hqeO
					aKZsUFfpX8cNcFtGEywfHndCPELbRxFeEziP
					utqHFLPNMX5nYCpS28w4oJ5sAnM= )
			1800	TXT	"Doing It Safe Is Better"
			1800	RRSIG	TXT 8 2 1800 (
					20160428190224 20160329190224 14460 dnssex.nl.
					f6S+DUfJK1UYdOb3AHgUXzFTTtu+yLp/Fv7S
					Hv0CAGhXAVw+nBbK719igFvBtObS33WKwzxD
					1pQNMaJcS6zeevtD+4PKB1KDC4fyJffeEZT6
					E30jGR8Y29/xA+Fa4lqDNnj9zP3b8TiABCle
					ascY5abkgWCALLocFAzFJQ/27YQ= )
			1800	AAAA	2a01:7e00::f03c:91ff:fef1:6735
			1800	RRSIG	AAAA 8 2 1800 (
					20160428190224 20160329190224 14460 dnssex.nl.
					PWcPSawEUBAfCuv0liEOQ8RYe7tfNW4rubIJ
					LE+dbrub1DUer3cWrDoCYFtOufvcbkYJQ2CQ
					AGjJmAQ5J2aqYDOPMrKa615V0KT3ifbZJcGC
					gkIic4U/EXjaQpRoLdDzR9MyVXOmbA6sKYzj
					ju1cNkLqM8D7Uunjl4pIr6rdSFo= )
			14400	NSEC	*.dnssex.nl. A NS SOA TXT AAAA RRSIG NSEC DNSKEY
			14400	RRSIG	NSEC 8 2 14400 (
					20160428190224 20160329190224 14460 dnssex.nl.
					oIvM6JZIlNc1aNKGTxv58ApSnDr1nDPPgnD9
					9oJZRIn7eb5WnpeDz2H3z5+x6Bhlp5hJJaUp
					KJ3Ss6Jg/IDnrmIvKmgq6L6gHj1Y1IiHmmU8
					VeZTRzdTsDx/27OsN23roIvsytjveNSEMfIm
					iLZ23x5kg1kBdJ9p3xjYHm5lR+8= )
			1800	DNSKEY	256 3 8 (
					AwEAAazSO6uvLPEVknDA8yxjFe8nnAMU7txp
					wb19k55hQ81WV3G4bpBM1NdN6sbYHrkXaTNx
					2bQWAkvX6pz0XFx3z/MPhW+vkakIWFYpyQ7R
					AT5LIJfToVfiCDiyhhF0zVobKBInO9eoGjd9
					BAW3TUt+LmNAO/Ak5D5BX7R3CuA7v9k7
					) ; ZSK; alg = RSASHA256; key id = 14460
			1800	DNSKEY	257 3 8 (
					AwEAAbyeaV9zg0IqdtgYoqK5jJ239anzwG2i
					gvH1DxSazLyaoNvEkCIvPgMLW/JWfy7Z1mQp
					SMy9DtzL5pzRyQgw7kIeXLbi6jufUFd9pxN+
					xnzKLf9mY5AcnGToTrbSL+jnMT67wG+c34+Q
					PeVfucHNUePBxsbz2+4xbXiViSQyCQGv
					) ; KSK; alg = RSASHA256; key id = 18772
			1800	RRSIG	DNSKEY 8 2 1800 (
					20160428190224 20160329190224 14460 dnssex.nl.
					cFSFtJE+DBGNxb52AweFaVHBe5Ue5MDpqNdC
					TIneUnEhP2m+vK4zJ/TraK0WdQFpsX63pod8
					PZ9y03vHUfewivyonCCBD3DcNdoU9subhN22
					tez9Ct8Z5/9E4RAz7orXal4M1VUEhRcXSEH8
					SJW20mfVsqJAiKqqNeGB/pAj23I= )
			1800	RRSIG	DNSKEY 8 2 1800 (
					20160428190224 20160329190224 18772 dnssex.nl.
					oiiwo/7NYacePqohEp50261elhm6Dieh4j2S
					VZGAHU5gqLIQeW9CxKJKtSCkBVgUo4cvO4Rn
					2tzArAuclDvBrMXRIoct8u7f96moeFE+x5FI
					DYqICiV6k449ljj9o4t/5G7q2CRsEfxZKpTI
					A/L0+uDk0RwVVzL45+TnilcsmZs= )
*.dnssex.nl.		1800	IN TXT	"Doing It Safe Is Better"
			1800	RRSIG	TXT 8 2 1800 (
					20160428190224 20160329190224 14460 dnssex.nl.
					FUZSTyvZfeuuOpCmNzVKOfITRHJ6/ygjmnnb
					XGBxVUyQjoLuYXwD5XqZWGw4iKH6QeSDfGCx
					4MPqA4qQmW7Wwth7mat9yMfA4+p2sO84bysl
					7/BG9+W2G+q1uQiM9bX9V42P2X/XuW5Y/t9Y
					8u1sljQ7D8WwS6naH/vbaJxnDBw= )
			14400	NSEC	a.dnssex.nl. TXT RRSIG NSEC
			14400	RRSIG	NSEC 8 2 14400 (
					20160428190224 20160329190224 14460 dnssex.nl.
					os6INm6q2eXknD5z8TpfbK00uxVbQefMvHcR
					/RNX/kh0xXvzAaaDOV+Ge/Ko+2dXnKP+J1LY
					G9ffXNpdbaQy5ygzH5F041GJst4566GdG/jt
					7Z7vLHYxEBTpZfxo+PLsXQXH3VTemZyuWyDf
					qJzafXJVH1F0nDrcXmMlR6jlBHA= )
www.dnssex.nl.		1800	IN CNAME a.dnssex.nl.
			1800	RRSIG	CNAME 8 3 1800 (
					20160428190224 20160329190224 14460 dnssex.nl.
					Omv42q/uVvdNsWQoSrQ6m6w6U7r7Abga7uF4
					25b3gZlse0C+WyMyGFMGUbapQm7azvBpreeo
					uKJHjzd+ufoG+Oul6vU9vyoj+ejgHzGLGbJQ
					HftfP+UqP5SWvAaipP/LULTWKPuiBcLDLiBI
					PGTfsq0DB6R+qCDTV0fNnkgxEBQ= )
			14400	NSEC	dnssex.nl. CNAME RRSIG NSEC
			14400	RRSIG	NSEC 8 3 14400 (
					20160428190224 20160329190224 14460 dnssex.nl.
					TBN3ddfZW+kC84/g3QlNNJMeLZoyCalPQylt
					KXXLPGuxfGpl3RYRY8KaHbP+5a8MnHjqjuMB
					Lofb7yKMFxpSzMh8E36vnOqry1mvkSakNj9y
					9jM8PwDjcpYUwn/ql76MsmNgEV5CLeQ7lyH4
					AOrL79yOSQVI3JHJIjKSiz88iSw= )
a.dnssex.nl.		1800	IN A	139.162.196.78
			1800	RRSIG	A 8 3 1800 (
					20160428190224 20160329190224 14460 dnssex.nl.
					OXHpFj9nSpKi5yA/ULH7MOpGAWfyJ2yC/2xa
					Pw0fqSY4QvcRt+V3adcFA4H9+P1b32GpxEjB
					lXmCJID+H4lYkhUR4r4IOZBVtKG2SJEBZXip
					pH00UkOIBiXxbGzfX8VL04v2G/YxUgLW57kA
					aknaeTOkJsO20Y+8wmR9EtzaRFI= )
			1800	AAAA	2a01:7e00::f03c:91ff:fef1:6735
			1800	RRSIG	AAAA 8 3 1800 (
					20160428190224 20160329190224 14460 dnssex.nl.
					jrepc/VnRzJypnrG0WDEqaAr3HMjWrPxJNX0
					86gbFjZG07QxBmrA1rj0jM9YEWTjjyWb2tT7
					lQhzKDYX/0XdOVUeeOM4FoSks80V+pWR8fvj
					AZ5HmX69g36tLosMDKNR4lXcrpv89QovG4Hr
					/r58fxEKEFJqrLDjMo6aOrg+uKA= )
			14400	NSEC	www.dnssex.nl. A AAAA RRSIG NSEC
			14400	RRSIG	NSEC 8 3 14400 (
					20160428190224 20160329190224 14460 dnssex.nl.
					S+UM62wXRNNFN3QDWK5YFWUbHBXC4aqaqinZ
					A2ZDeC+IQgyw7vazPz7cLI5T0YXXks0HTMlr
					soEjKnnRZsqSO9EuUavPNE1hh11Jjm0fB+5+
					+Uro0EmA5Dhgc0Z2VpbXVQEhNDf/pI1gem15
					RffN2tBYNykZn4Has2ySgRaaRYQ= )`

	var dnssexAuth = []dns.RR{
		ns("dnssex.nl.	1800	IN	NS	linode.atoom.net."),
		ns("dnssex.nl.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
		ns("dnssex.nl.	1800	IN	NS	omval.tednet.nl."),
		rrsig("dnssex.nl.	1800	IN	RRSIG	NS 8 2 1800 20160428190224 20160329190224 14460 dnssex.nl. dLIeEvP86jj5ndkcLzhgvWixTABjWAGRTGQsPsVDFXsGMf9TGGC9FEomgkCVeNC0="),
	}

	var dnsTestCases = []testCase{
		{
			Qname: "wild.dnssex.nl.", Qtype: dns.TypeTXT,
			Answer: []dns.RR{
				txt(`wild.dnssex.nl.	1800	IN	TXT	"Doing It Safe Is Better"`),
			},
			Ns: dnssexAuth[:len(dnssexAuth)-1], // remove RRSIG on the end
		},
		{
			Qname: "a.wild.dnssex.nl.", Qtype: dns.TypeTXT,
			Answer: []dns.RR{
				txt(`a.wild.dnssex.nl.	1800	IN	TXT	"Doing It Safe Is Better"`),
			},
			Ns: dnssexAuth[:len(dnssexAuth)-1], // remove RRSIG on the end
		},
		/*
			{
				Qname: "wild.dnssex.nl.", Qtype: dns.TypeTXT, Do: true,
				Answer: []dns.RR{
					rrsig("wild.dnssex.nl.	1800	IN	RRSIG	TXT 8 2 1800 20160428190224 20160329190224 14460 dnssex.nl. FUZSTyvZfeuuOpCm"),
					txt(`wild.dnssex.nl.	1800	IN	TXT	"Doing It Safe Is Better"`),
				},
				Ns: append([]dns.RR{
					nsec("a.dnssex.nl.	14400	IN	NSEC	www.dnssex.nl. A AAAA RRSIG NSEC"),
					rrsig("a.dnssex.nl.	14400	IN	RRSIG	NSEC 8 3 14400 20160428190224 20160329190224 14460 dnssex.nl. S+UMs2ySgRaaRY"),
				}, dnssexAuth...),
				Extra: []dns.RR{opt(4096, true)},
			},
		*/
		/*
			{
				Qname: "a.wild.dnssex.nl.", Qtype: dns.TypeTXT, Do: true,
				Answer: []dns.RR{
					rrsig("a.wild.dnssex.nl.	1800	IN	RRSIG	TXT 8 2 1800 20160428190224 20160329190224 14460 dnssex.nl. FUZSTyvZfeuuOpCm"),
					txt(`a.wild.dnssex.nl.	1800	IN	TXT	"Doing It Safe Is Better"`),
				},
				Ns: append([]dns.RR{
					nsec("a.dnssex.nl.	14400	IN	NSEC	www.dnssex.nl. A AAAA RRSIG NSEC"),
					rrsig("a.dnssex.nl.	14400	IN	RRSIG	NSEC 8 3 14400 20160428190224 20160329190224 14460 dnssex.nl. S+UMs2ySgRaaRY"),
				}, dnssexAuth...),
				Extra: []dns.RR{opt(4096, true)},
			},
			// nodata responses
			{
				Qname: "wild.dnssex.nl.", Qtype: dns.TypeSRV,
				Ns: []dns.RR{
					soa(`dnssex.nl.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1459281744 14400 3600 604800 14400`),
				},
			},
			{
				Qname: "wild.dnssex.nl.", Qtype: dns.TypeSRV, Do: true,
				Ns: []dns.RR{
					// TODO(miek): needs closest encloser proof as well? This is the wrong answer
					nsec(`*.dnssex.nl.	14400	IN	NSEC	a.dnssex.nl. TXT RRSIG NSEC`),
					rrsig(`*.dnssex.nl.	14400	IN	RRSIG	NSEC 8 2 14400 20160428190224 20160329190224 14460 dnssex.nl. os6INm6q2eXknD5z8TaaDOV+Ge/Ko+2dXnKP+J1fqJzafXJVH1F0nDrcXmMlR6jlBHA=`),
					rrsig(`dnssex.nl.	1800	IN	RRSIG	SOA 8 2 1800 20160428190224 20160329190224 14460 dnssex.nl. CA/Y3m9hCOiKC/8ieSOv8SeP964Bq++lyH8BZJcTaabAsERs4xj5PRtcxicwQXZiF8fYUCpROlUS0YR8Cdw=`),
					soa(`dnssex.nl.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1459281744 14400 3600 604800 14400`),
				},
				Extra: []dns.RR{opt(4096, true)},
			},
		*/
	}

	router := New()
	router.HandleZone(strings.NewReader(s), "dnssex.nl.", "stdin")

	for _, tc := range dnsTestCases {
		resp := new(responseWriter)
		req := &Request{Msg: tc.Msg()}
		ChainHandler(router, DefaultScheme...).ServeDNS(resp, req)
		sortAndCheck(t, &resp.msg, tc)
	}
}

func TestLookupDoubleWildcard(t *testing.T) {
	const s = `; example.org test file
$TTL 3600
example.org.		IN	SOA	sns.dns.icann.org. noc.dns.icann.org. 2015082541 7200 3600 1209600 3600
example.org.		IN	NS	b.iana-servers.net.
example.org.		IN	NS	a.iana-servers.net.
example.org.		IN	A	127.0.0.1
example.org.		IN	A	127.0.0.2
*.w.example.org.        IN      TXT     "Wildcard"
a.b.c.w.example.org.    IN      TXT     "Not a wildcard"
*.c.example.org.        IN      TXT     "c Wildcard"
*.d.example.org.        IN      CNAME   alias.example.org.
alias.example.org.      IN      TXT     "Wildcard CNAME expansion"
`
	var exampleAuth = []dns.RR{
		ns("example.org.	3600	IN	NS	a.iana-servers.net."),
		ns("example.org.	3600	IN	NS	b.iana-servers.net."),
	}

	var dnsTestCases = []testCase{
		{
			Qname: "wild.w.example.org.", Qtype: dns.TypeTXT,
			Answer: []dns.RR{
				txt(`wild.w.example.org. IN	TXT	"Wildcard"`),
			},
			Ns: exampleAuth,
		},
		{
			Qname: "wild.c.example.org.", Qtype: dns.TypeTXT,
			Answer: []dns.RR{
				txt(`wild.c.example.org. IN	TXT	"c Wildcard"`),
			},
			Ns: exampleAuth,
		},
		{
			Qname: "wild.d.example.org.", Qtype: dns.TypeTXT,
			Answer: []dns.RR{
				txt(`alias.example.org. IN	TXT	"Wildcard CNAME expansion"`),
				cname(`wild.d.example.org. IN	CNAME	alias.example.org`),
			},
			Ns: exampleAuth,
		},
		{
			Qname: "alias.example.org.", Qtype: dns.TypeTXT,
			Answer: []dns.RR{
				txt(`alias.example.org. IN	TXT	"Wildcard CNAME expansion"`),
			},
			Ns: exampleAuth,
		},
	}

	router := New()
	router.HandleZone(strings.NewReader(s), "example.org.", "stdin")

	for _, tc := range dnsTestCases {
		resp := new(responseWriter)
		req := &Request{Msg: tc.Msg()}
		ChainHandler(router, DefaultScheme...).ServeDNS(resp, req)
		sortAndCheck(t, &resp.msg, tc)
	}
}

func TestLookupApexWildcard(t *testing.T) {
	const s = `; example.org test file with wildcard at apex
$TTL 3600
example.org.		IN	SOA	sns.dns.icann.org. noc.dns.icann.org. 2015082541 7200 3600 1209600 3600
example.org.		IN	NS	b.iana-servers.net.
*.example.org.          IN      A       127.0.0.53
foo.example.org.        IN      A       127.0.0.54
`
	var dnsTestCases = []testCase{
		{
			Qname: "foo.example.org.", Qtype: dns.TypeA,
			Answer: []dns.RR{a(`foo.example.org. 3600	IN	A 127.0.0.54`)},
			Ns: []dns.RR{ns(`example.org. 3600 IN NS b.iana-servers.net.`)},
		},
		{
			Qname: "bar.example.org.", Qtype: dns.TypeA,
			Answer: []dns.RR{a(`bar.example.org. 3600	IN	A 127.0.0.53`)},
			Ns: []dns.RR{ns(`example.org. 3600 IN NS b.iana-servers.net.`)},
		},
	}

	router := New()
	router.HandleZone(strings.NewReader(s), "example.org.", "stdin")

	for _, tc := range dnsTestCases {
		resp := new(responseWriter)
		req := &Request{Msg: tc.Msg()}
		ChainHandler(router, DefaultScheme...).ServeDNS(resp, req)
		sortAndCheck(t, &resp.msg, tc)
	}
}

func TestLookupMultiWildcard(t *testing.T) {
	const s = `; example.org test file with wildcard at apex
$TTL 3600
example.org.		IN	SOA	sns.dns.icann.org. noc.dns.icann.org. 2015082541 7200 3600 1209600 3600
example.org.		IN	NS	b.iana-servers.net.
*.example.org.          IN      A       127.0.0.53
*.intern.example.org.   IN      A       127.0.1.52
foo.example.org.        IN      A       127.0.0.54
`
	var dnsTestCases = []testCase{
		{
			Qname: "foo.example.org.", Qtype: dns.TypeA,
			Answer: []dns.RR{a(`foo.example.org. 3600	IN	A 127.0.0.54`)},
			Ns: []dns.RR{ns(`example.org. 3600 IN NS b.iana-servers.net.`)},
		},
		{
			Qname: "bar.example.org.", Qtype: dns.TypeA,
			Answer: []dns.RR{a(`bar.example.org. 3600	IN	A 127.0.0.53`)},
			Ns: []dns.RR{ns(`example.org. 3600 IN NS b.iana-servers.net.`)},
		},
		{
			Qname: "bar.intern.example.org.", Qtype: dns.TypeA,
			Answer: []dns.RR{a(`bar.intern.example.org. 3600	IN	A 127.0.1.52`)},
			Ns: []dns.RR{ns(`example.org. 3600 IN NS b.iana-servers.net.`)},
		},
	}

	router := New()
	router.HandleZone(strings.NewReader(s), "example.org.", "stdin")

	for _, tc := range dnsTestCases {
		resp := new(responseWriter)
		req := &Request{Msg: tc.Msg()}
		ChainHandler(router, DefaultScheme...).ServeDNS(resp, req)
		sortAndCheck(t, &resp.msg, tc)
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
