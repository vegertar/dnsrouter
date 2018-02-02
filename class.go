package dnsrouter

import "github.com/miekg/dns"

// A Stub is a name server.
type Stub interface {
	Lookup(name string, qclass uint16) (class Class)
}

// A Class is acquired from a Stub via an arbitrary name with a class.
type Class interface {
	NextSecure(nsecType uint16) (nsec Class)
	Search(qtype uint16) (h Handler)
	Stub() (stub Stub)
	Zone() (zone Class, delegated bool)
}

// CheckRedirect is useful for checking type assertion on a Handle that
// returned from a Search if which occurs DNAME or CNAME redirection.
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
	return c.handler != nil || c.cut && len(c.zones) > 0
}

func (c basicClass) Search(qtype uint16) Handler {
	switch c.searchMode {
	case searchAny:
		if qtype == dns.TypeANY {
			if h := c.handler; h != nil {
				return ParamsHandler(h, c.params)
			}
		} else {
			if qtype != dns.TypeRRSIG && qtype != dns.TypeNSEC {
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
	if i := len(c.zones); i > 0 {
		zone := c.zones[i-1]
		c.handler = zone.node.data.handler
		c.params = zone.params
		c.zones = c.zones[:i-1]
		c.cut = false
		return c, zone.node.data.rrType&rrSoa == 0
	}
	return nil, false
}

func (c basicClass) NextSecure(qtype uint16) Class {
	if qtype == dns.TypeNSEC {
		node := c.value.previous()
		if node != nil && node.data != nil {
			c.handler = node.data.handler
			c.params = nil
			c.searchMode = searchAny
			return c
		}
	}

	return nil
}

func (c basicClass) Stub() Stub {
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
