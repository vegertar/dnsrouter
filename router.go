package dnsrouter

import (
	"context"
	"io"
	"os"
	"path"

	"github.com/miekg/dns"
)

// Router is a dns Handler which can be used to dispatch requests to different
// handler functions via configurable routes.
type Router struct {
	trees map[uint16]*node

	// Configurable middleware that chaining with the Router.
	// If it is nil, then uses DefaultScheme.
	Middleware []Middleware
}

// Making sure the Router conforms with the dns.Handler interface.
var _ Handler = new(Router)

// New returns a new initialized Router.
func New() *Router {
	return &Router{
		trees: make(map[uint16]*node),
	}
}

// Handle registers a new request handler with a routing pattern, any string that
// can pass into dns.NewRR is legal to use in here.
// Only a domain that beginning with a single asterisk (*) is treated as wildcard
// (https://tools.ietf.org/html/rfc4592), in other cases, wildcard labels or
// named parameters are treated as same as path components used in httprouter
// (https://github.com/julienschmidt/httprouter).
// If the handler is nil then defaults to write the resulted record into answer section.
// Please pay attention that Handle won't check if the given string contains an actual
// record data, e.g. "github.com A" is legal to pass to Handle, so calling
// Handle("github.com A", nil) causes a strange RR "github.com. 3600 IN A " in ANSWER section.
func (r *Router) Handle(s string, handler Handler) {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	if handler == nil {
		handler = Answer{rr}
	}

	if rr == nil {
		panic("nil RR: " + s)
	}

	hdr := rr.Header()

	var typeCovered uint16
	if hdr.Rrtype == dns.TypeRRSIG {
		typeCovered = rr.(*dns.RRSIG).TypeCovered
	}
	r.handle(hdr.Name, hdr.Class, typeHandler{
		Qtype:       hdr.Rrtype,
		TypeCovered: typeCovered,
		Handler:     handler,
	})
}

// HandleFunc registers a new request handler function with a routing pattern.
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

		rr := x.RR
		hdr := rr.Header()

		var typeCovered uint16
		if hdr.Rrtype == dns.TypeRRSIG {
			typeCovered = rr.(*dns.RRSIG).TypeCovered
		}
		r.handle(hdr.Name, hdr.Class, typeHandler{
			Origin:      origin,
			Qtype:       hdr.Rrtype,
			TypeCovered: typeCovered,
			Handler:     Answer{rr},
		})
	}
}

func (r *Router) handle(name string, qclass uint16, handler typeHandler) {
	if name == "" || len(name) > 1 && isIndexable(name) {
		panic(name + ": illegal domain")
	}
	if handler.Handler == nil {
		panic(name + ": missing Handler")
	}

	root := r.trees[qclass]
	if root == nil {
		root = new(node)
		r.trees[qclass] = root
	}

	indexableName := newIndexableName(name)
	root.addRoute(indexableName, true, handler)
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
