package dnsrouter

import "github.com/miekg/dns"

// A Stub is a name server.
type Stub interface {
	Lookup(name string, qclass uint16) Class
}

// A Class is acquired from a Stub via an arbitrary name with a class.
type Class interface {
	Zone() (c Class, delegated bool)
	NextSecure(nsecType uint16) Class
	Search(qtype uint16) Handler
	Invert() Stub
}

// CheckRedirect is useful for checking if occurs DNAME or CNAME redirection.
type CheckRedirect interface {
	Qtype() uint16
}

type classContextKeyType int

// ClassContextKey is used to get Class instance from Request context.
const ClassContextKey classContextKeyType = 1

type classSearchMode uint8

const (
	searchAny classSearchMode = iota // default
	searchCovered
)

type basicClass struct {
	value
	stub       Stub
	handler    classHandler
	params     Params
	searchMode classSearchMode
}

func (c basicClass) isAvailable() bool {
	return c.handler != nil || c.cut && c.zone.node != nil
}

func (c basicClass) Search(qtype uint16) Handler {
	switch c.searchMode {
	case searchAny:
		if qtype == dns.TypeANY {
			if h := c.handler; h != nil {
				return ParamsHandler(h, c.params)
			}
		} else {
			if qtype != dns.TypeRRSIG {
				// DNAME redirection
				if c.node != nil && c.node.data.rrType&rrDname > 0 && c.cut {
					h := ParamsHandler(c.handler.Search(dns.TypeDNAME), c.params)
					if qtype == dns.TypeDNAME {
						return h
					}
					return basicType{Handler: h, qtype: dns.TypeDNAME}
				}

				// CNAME redirection
				if v := c.handler.Search(dns.TypeCNAME); v != nil {
					h := ParamsHandler(v, c.params)
					if qtype == dns.TypeCNAME {
						return h
					}
					return basicType{Handler: h, qtype: dns.TypeCNAME}
				}
			}

			if h := c.handler.Search(qtype); h != nil {
				if qtype == dns.TypeRRSIG {
					c.searchMode = searchCovered
					c.handler = h
					return c
				}

				return ParamsHandler(h, c.params)
			}
		}
	case searchCovered:
		if h := c.handler.SearchCovered(qtype); h != nil {
			return ParamsHandler(h, c.params)
		}
	}

	if c.isAvailable() {
		return NoErrorHandler
	}
	return NameErrorHandler
}

func (c basicClass) Zone() (Class, bool) {
	if c.zone.node != nil {
		c.handler = c.zone.node.data.handler
		c.params = c.zone.params
		c.cut = false
		return c, c.zone.node.data.rrType&rrSoa == 0
	}
	return nil, false
}

func (c basicClass) NextSecure(_ uint16) Class {
	return nil
}

func (c basicClass) Invert() Stub {
	return c.stub
}

func (c basicClass) ServeDNS(w ResponseWriter, r *Request) {
	var h Handler
	if c.handler != nil {
		h = ParamsHandler(c.handler, c.params)
	} else if c.isAvailable() {
		h = NoErrorHandler
	} else {
		h = NameErrorHandler
	}

	h.ServeDNS(w, r)
}

type basicType struct {
	Handler
	qtype uint16
}

func (t basicType) Qtype() uint16 {
	return t.qtype
}
