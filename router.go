package dnsrouter

import (
	"context"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// Router is a dns Handler which can be used to dispatch requests to different
// handler functions via configurable routes.
type Router struct {
	trees      map[uint16]*node
	nsecNames  map[uint16]canonicalOrder
	nsec3Names map[uint16]canonicalOrder

	// Configurable middleware that chaining with the Router.
	// If it is nil, then uses DefaultScheme.
	Middleware []Middleware
}

// Making sure the Router conforms with the dns.Handler interface.
var _ Handler = new(Router)

// New returns a new initialized Router.
func New() *Router {
	return &Router{
		trees:      make(map[uint16]*node),
		nsec3Names: make(map[uint16]canonicalOrder),
		nsecNames:  make(map[uint16]canonicalOrder),
	}
}

// Handle registers a new request handler with the given domain or RR in string.
// Only a domain that beginning with a single asterisk (*) is treated as wildcard
// (https://tools.ietf.org/html/rfc4592), in other cases, wildcard labels or
// named parameters are treated as same as path components used in httprouter
// (https://github.com/julienschmidt/httprouter).
// If s is a literal string which is able to create a dns.RR by dns.NewRR, the
// handler is optional and defaults to write the resulted record into answer section.
// Please pay attention that Handle won't check if the given string contains an actual
// record data, e.g. "github.com A" is legal to pass to Handle, so calling
// Handle("github.com A", nil) causes a strange RR "github.com. 3600 IN A " in ANSWER section.
func (r *Router) Handle(s string, handler Handler) {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	if handler == nil {
		handler = Answer(rr)
	}

	if rr == nil {
		panic("nil RR: " + s)
	}

	hdr := rr.Header()

	var typeCovered uint16
	if hdr.Rrtype == dns.TypeRRSIG {
		typeCovered = rr.(*dns.RRSIG).TypeCovered
	}
	r.handle(hdr.Name, hdr.Class, hdr.Rrtype, typeCovered, handler)
}

// HandleFunc registers a new request handler function with the given domain or RR in string.
func (r *Router) HandleFunc(s string, handlerFunc HandlerFunc) {
	r.Handle(s, handlerFunc)
}

// HandleZoneFile loads a zone file.
func (r *Router) HandleZoneFile(origin, filename string) {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}

	r.HandleZone(f, origin, path.Base(filename))
}

// HandleZone loads a zone reader.
func (r *Router) HandleZone(f io.Reader, origin, filename string) {
	for x := range dns.ParseZone(f, dns.Fqdn(origin), filename) {
		if x.Error != nil {
			panic(x.Error)
		}

		r.Handle(x.RR.String(), nil)
	}
}

func (r *Router) handle(name string, qclass, qtype, typeCovered uint16, handler Handler) {
	if name == "" || len(name) > 1 && isIndexable(name) {
		panic(name + ": illegal domain")
	}
	if handler == nil {
		panic(name + ": missing Handler")
	}

	root := r.trees[qclass]
	if root == nil {
		root = new(node)
		r.trees[qclass] = root
	}

	indexableName := newIndexableName(name)
	root.addRoute(indexableName, true, typeHandler{
		Qtype:       qtype,
		TypeCovered: typeCovered,
		Handler:     handler,
	})

	if qtype == dns.TypeNSEC {
		r.nsecNames[qclass] = append(r.nsecNames[qclass], indexableName)
		sort.Sort(r.nsecNames[qclass])
	} else if qtype == dns.TypeNSEC3 {
		r.nsec3Names[qclass] = append(r.nsec3Names[qclass], indexableName)
		sort.Sort(r.nsec3Names[qclass])
	}
}

// nsecPrevious returns the previous routing item by canonical order.
func (r *Router) nsecPrevious(name string, qclass, qtype uint16) string {
	var previous string
	switch qtype {
	case dns.TypeNSEC3:
		previous, _ = r.nsec3Names[qclass].Previous(newIndexableName(name))
	case dns.TypeNSEC:
		previous, _ = r.nsecNames[qclass].Previous(newIndexableName(name))
	}
	return previous
}

// Lookup implements Stub interface, this method would never return nil.
func (r *Router) Lookup(name string, qclass uint16) Class {
	var c basicClass
	c.stub = r

	if root := r.trees[qclass]; root != nil {
		c.value = root.getValue(newIndexableName(name))
		c.value.revertParams()
		c.params = c.value.params
		if c.value.node != nil {
			c.handler = c.value.node.data.handler
		}
	}

	return c
}

// ServeDNS implements Handler interface.
func (r *Router) ServeDNS(resp ResponseWriter, req *Request) {
	class := r.Lookup(req.Question[0].Name, req.Question[0].Qclass)
	ctx := context.WithValue(req.Context(), ClassContextKey, class)
	middleware := r.Middleware
	if middleware == nil {
		middleware = DefaultScheme
	}
	ChainHandler(NoErrorHandler, middleware...).ServeDNS(resp, req.WithContext(ctx))
}

func newIndexableName(name string) string {
	if !isIndexable(name) {
		name = indexable(dns.Fqdn(name))
	}
	return name
}

func isIndexable(s string) bool {
	return s != "" && s[0] == '.'
}

func indexable(s string) string {
	if len(s) <= 1 {
		return s
	}

	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	reverseLabels(b)
	return string(b)
}

func reverseLabels(b []byte) {
	begin := -1
	for i := 0; i < len(b); i++ {
		if begin == -1 && b[i] != '.' {
			begin = i
		}
		if begin != -1 && (i+1 < len(b) && b[i+1] == '.' || i+1 == len(b)) {
			reveseChars(b[begin : i+1])
			begin = -1
		}
	}
	reveseChars(b)
}

func reveseChars(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

type canonicalOrder []string

func (l canonicalOrder) Len() int { return len(l) }

func (l canonicalOrder) Swap(a, b int) { l[a], l[b] = l[b], l[a] }

func (l canonicalOrder) Less(a, b int) bool {
	return canonicalOrderLess(l[a], l[b])
}

func (l canonicalOrder) Previous(name string) (string, bool) {
	if len(l) == 0 {
		return "", false
	}

	i := sort.Search(len(l), func(i int) bool {
		return !canonicalOrderLess(l[i], name)
	})
	found := i < len(l) && l[i] == name
	if i == 0 {
		i = len(l)
	}
	return l[i-1], found
}

func canonicalOrderLess(x, y string) bool {
	nX := strings.Count(x, ".")
	nY := strings.Count(y, ".")
	n := nX
	if n > nY {
		n = nY
	}

	for i := 0; i < n; i++ {
		xDot := strings.Index(x, ".")
		yDot := strings.Index(y, ".")

		var xI, yI string
		if xDot == -1 {
			xI = x
		} else {
			xI = x[:xDot]
			x = x[xDot+1:]
		}
		if yDot == -1 {
			yI = y
		} else {
			yI = y[:yDot]
			y = y[yDot+1:]
		}

		if xI != yI {
			if len(xI) > 1 && xI[0] == '*' {
				return false
			}
			if len(yI) > 1 && yI[0] == '*' {
				return true
			}
			if len(xI) > 1 && xI[0] == ':' && len(yI) > 1 && yI[0] == ':' {
				continue
			}
			if len(xI) > 1 && xI[0] == ':' {
				return false
			}
			if len(yI) > 1 && yI[0] == ':' {
				return true
			}
			return xI < yI
		}
	}
	if x != y {
		if len(x) > 1 && x[0] == '*' {
			return false
		}
		if len(y) > 1 && y[0] == '*' {
			return true
		}
		if len(x) > 1 && x[0] == ':' && len(y) > 1 && y[0] == ':' {
			return nX < nY
		}
		if len(x) > 1 && x[0] == ':' {
			return false
		}
		if len(y) > 1 && y[0] == ':' {
			return true
		}
	}
	return x < y
}
