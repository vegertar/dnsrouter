[![Build Status](https://travis-ci.org/vegertar/dnsrouter.svg?branch=master)](https://travis-ci.org/vegertar/dnsrouter)
[![codecov](https://codecov.io/gh/vegertar/dnsrouter/branch/master/graph/badge.svg)](https://codecov.io/gh/vegertar/dnsrouter)
[![Go Report Card](https://goreportcard.com/badge/github.com/vegertar/dnsrouter)](https://goreportcard.com/report/github.com/vegertar/dnsrouter)
[![GoDoc](https://godoc.org/github.com/vegertar/dnsrouter?status.svg)](https://godoc.org/github.com/vegertar/dnsrouter)
<!-- TOC -->

- [DnsRouter](#dnsrouter)
    - [Features](#features)
    - [Dependencies](#dependencies)
    - [Install](#install)
    - [Usage](#usage)
        - [Named parameters & Catch-All parameters](#named-parameters--catch-all-parameters)
    - [Benchmarks](#benchmarks)
        - [Without DNSSEC](#without-dnssec)
        - [With DNSSEC](#with-dnssec)
    - [TODO](#todo)

<!-- /TOC -->
# DnsRouter

DnsRouter is a lightweight high performance DNS request router with chaining middlewares.

Highly inspired by julienschmidt's [HttpRouter](https://github.com/julienschmidt/httprouter) and miekg's [CoreDNS](https://github.com/coredns/coredns), actually, this router is developed upon HttpRouter's extreamely fast radix tree, and passed all test cases of [file](https://github.com/coredns/coredns/blob/master/plugin/file) plugin from CoreDNS.

In contrast to CoreDNS which is a complete DNS server, DnsRouter is targeting a library of a tree of stub name servers, all other resolving functions like filling out `ANSWER`, `AUTHORITY`, `ADDITIONAL` sections are designed as middlewares, which makes name server efficient and flexible.

## Features

**Named parameters in routing patterns**: Directly inheriting parameterized patterns from [HttpRouter](https://github.com/julienschmidt/httprouter), includes both `:param` and `*catchAll`, anyone who confuses [wildcard DNS records](https://en.wikipedia.org/wiki/Wildcard_DNS_record) or used to conventional HTTP mux patterns would feel easy to use it.

**Anonymous parameters in routing patterns**: Against *named parameters in routing patterns*, an anonymous asterisk in the beginning of domain patterns, e.g. `*.`, is interpreted in DNS wildcard semantics, as [RFC 4592](https://tools.ietf.org/html/rfc4592), which makes DnsRouter compatible with traditional DNS wildcard matching rules.

**Multi-Zone in one tree**: A router instance could safely contain multiple zones simultaneously, the underlying radix tree promises the best performance if you have lots of records with lots of domains, or zones.

**Nearly Zero Garbage**: As [HttpRouter](https://github.com/julienschmidt/httprouter), the tree related processes generate zero bytes of garbage, the actual up to 4 more heap allocations that are made, is from zone slice (1 alloc), domain name reversing (2 allocs), and a returning of an interface (1 alloc).

**Out-of-box stub name server**: The builtin middlewares are organzied into two schemes, `DefaultScheme` and `SimpleScheme`. Use these schemes make DnsRouter working as an out-of-box stub name server, i.e. looking up name records, following CNAME redirections, expanding wildcards, supplying DNSSEC RRset and recovering panic, etc. What the different of `DefaultScheme` and `SimpleScheme` is that the later doesn't filling out `AUTHORITY` and `ADDITIONAL` sections.

**Chaining middlewares**: DnsRoute scales well by chaining middlewares, enjoyly choose what you need from builtin middlewares or implement your owns to extend stub name server, e.g. a recursive resolver or cache.

**Fast**: [Benchmarks](#benchmarks) show DnsRouter is **2x to 4x** faster than [file](https://github.com/coredns/coredns/blob/master/plugin/file) plugin of CoreDNS.

## Dependencies

Golang 1.9.x and miekg's awesome [DNS library](https://github.com/miekg/dns).

## Install

Using the default `go tool` commands:

```bash
go get -v github.com/vegertar/dnsrouter
```

## Usage

Let's start with a trivial example:

```go
package main

import (
	"context"

	"github.com/miekg/dns"
	"github.com/vegertar/dnsrouter"
)

func main() {
	router := dnsrouter.New()
	router.HandleFunc("local A", func(w dnsrouter.ResponseWriter, req *dnsrouter.Request) {
		lo, err := dns.NewRR("local A 127.0.0.1")
		if err != nil {
			panic(err)
		}

		result := w.Msg()
		result.Answer = append(result.Answer, lo)
	})

	err := dns.ListenAndServe(":10053", "udp", dnsrouter.Classic(context.Background(), router))
	if err != nil {
		panic(err)
	}
}
```

Tests with `dig` command and omits unnecessary output, the sample print is shown below.

```bash
$ dig @127.0.0.1 -p 10053 local

;; ANSWER SECTION:
local.                  3600    IN      A       127.0.0.1
```

Then adds a SRV record.

```go
	srv := new(dns.SRV)
	srv.Hdr.Name = "_dns._udp."
	srv.Hdr.Rrtype = dns.TypeSRV
	srv.Hdr.Class = dns.ClassINET
	srv.Port = 10053
	srv.Target = "local."

	router.HandleFunc("local. SRV", func(w dnsrouter.ResponseWriter, req *dnsrouter.Request) {
		result := w.Msg()
		result.Answer = append(result.Answer, srv)
	})
```

`dig` with `SRV` could display the service, with additional A record that we set before as well.

```bash
$ dig @127.0.0.1 -p 10053 local SRV

;; ANSWER SECTION:
_dns._udp.              0       IN      SRV     0 0 10053 local.

;; ADDITIONAL SECTION:
local.                  3600    IN      A       127.0.0.1
```

Alternatively, you could try `dig` with `ANY` type.

```bash
$ dig @127.0.0.1 -p 10053 local ANY

;; ANSWER SECTION:
local.                  3600    IN      A       127.0.0.1
_dns._udp.              0       IN      SRV     0 0 10053 local.
```

Wants to known what happends when raises an exception? Adds some lines like below.

```go
	router.HandleFunc("local. SRV", func(w dnsrouter.ResponseWriter, req *dnsrouter.Request) {
		panic("oops: an exception")
	})
```

`dig` with `SRV` option again.

```bash
$ dig @127.0.0.1 -p 10053 local. SRV

;; ANSWER SECTION:
_dns._udp.              0       IN      SRV     0 0 10053 local.

;; ADDITIONAL SECTION:
local.                  0       IN      TXT     "panic" "oops: an exception" "main.main.func3:35"
```

This time the ADDITIONAL section contains a TXT record instead, which describes errors in shortly, includes a flag literal string "panic", an error message, and the trace information.

All above records are writing out by builtin middlewares, but there is no logging middleware to log every incoming DNS queries, let's implement a simple logger in here.

```go
func LoggerHandler(h dnsrouter.Handler) dnsrouter.Handler {
	return dnsrouter.HandlerFunc(func(w dnsrouter.ResponseWriter, req *dnsrouter.Request) {
		since := time.Now()
		q := req.Question[0]

		defer func() {
			log.Printf(`"%s %s %s" %s %v`,
				dns.TypeToString[q.Qtype],
				dns.ClassToString[q.Qclass],
				q.Name,
				dns.RcodeToString[w.Msg().Rcode],
				time.Since(since).String())
		}()

		h.ServeDNS(w, req)
	})
}
```

Then insert the `LoggerHandler` into chains.

```go
	router.Middleware = append(router.Middleware, LoggerHandler)
	router.Middleware = append(router.Middleware, dnsrouter.DefaultScheme...)
```

Running and testing again.

```bash
$ go run a.go
2018/02/05 15:57:01 "SRV IN local." SERVFAIL 46.248µs
2018/02/05 15:57:07 "A IN local." NOERROR 139.3µs
2018/02/05 15:57:10 "ANY IN local." SERVFAIL 204.684µs
2018/02/05 15:58:41 "A IN hello." REFUSED 34.333µs
```

### Named parameters & Catch-All parameters

These features are derived from [HttpRouter](https://github.com/julienschmidt/httprouter), the only difference is that DnsRouter uses dot ('.') as the label separator, and matches from right to left.

```bash
Pattern: :user.example.org.

joe.example.org                 match, captures "joe"
lily.example.org                match, captures "lily"
zuck.mark.example.org           no match
example.org.                    no match
```

```bash
Pattern: *user.example.org.

joe.example.org                 match, captures "joe."
lily.example.org                match, captures "lily."
zuck.mark.example.org           match, captures "zuck.mark."
example.org.                    no match
.example.org.                   match, captures ".", but an illegal domain
```

## Benchmarks

The testing environment is running on Ubuntu-16.04-amd64 with i7-7700HQ CPU @ 2.80GHz. Since all test cases are completely copied from `file` plugin of CoreDNS, so the bench codes are the same as well.

### Without DNSSEC

For `DnsRouter`:
```bash
$ go test -v -benchmem -run=^$ github.com/vegertar/dnsrouter -bench ^BenchmarkLookup$

goos: linux
goarch: amd64
pkg: github.com/vegertar/dnsrouter
BenchmarkLookup/DefaultScheme-8         	  300000	      5842 ns/op	    3264 B/op	      57 allocs/op
BenchmarkLookup/SimpleScheme-8          	  500000	      2824 ns/op	    1632 B/op	      29 allocs/op
PASS
ok  	github.com/vegertar/dnsrouter	3.254s
Success: Benchmarks passed.
```

For `file` plugin of CoreDNS:
```bash
$ go test -benchmem -run=^$ github.com/coredns/coredns/plugin/file -bench ^BenchmarkFileLookup$

goos: linux
goarch: amd64
pkg: github.com/coredns/coredns/plugin/file
BenchmarkFileLookup-8   	  100000	     14265 ns/op	    6243 B/op	      99 allocs/op
PASS
ok  	github.com/coredns/coredns/plugin/file	1.591s
Success: Benchmarks passed.
```

### With DNSSEC

For `DnsRouter`:
```bash
$ go test -v -benchmem -run=^$ github.com/vegertar/dnsrouter -bench ^BenchmarkLookupDNSSEC$

goos: linux
goarch: amd64
pkg: github.com/vegertar/dnsrouter
BenchmarkLookupDNSSEC-8   	  300000	      5605 ns/op	    3312 B/op	      56 allocs/op
PASS
ok  	github.com/vegertar/dnsrouter	1.747s
Success: Benchmarks passed.
```

For `file` plugin of CoreDNS:
```bash
$ go test -benchmem -run=^$ github.com/coredns/coredns/plugin/file -bench ^BenchmarkFileLookupDNSSEC$

goos: linux
goarch: amd64
pkg: github.com/coredns/coredns/plugin/file
BenchmarkFileLookupDNSSEC-8   	  100000	     21723 ns/op	    9163 B/op	     232 allocs/op
PASS
ok  	github.com/coredns/coredns/plugin/file	2.419s
Success: Benchmarks passed.
```

## TODO

There are some works in planed:

- NSEC3
- 100% code coverage
- Better examples and docs.

Any contributions are wellcome.
