package dnsrouter

import (
	"io"
	"os"
	"path"
	"strings"
	"unsafe"

	"github.com/miekg/dns"
)

const wildcardDomainPlaceholder = ":1"

type paramContextKeyType string

// Param is a single domain parameter, consisting of a key and a value.
type Param struct {
	Key   string
	Value string
}

// Params is a Param-slice, as returned by the router.
// The slice is ordered, the first domain parameter is also the first slice value.
// It is therefore safe to read values by the index.
type Params []Param

// ByName returns the value of the first Param which key matches the given name.
// If no matching Param is found, an empty string is returned.
func (ps Params) ByName(name string) string {
	for i := range ps {
		if ps[i].Key == name {
			return ps[i].Value
		}
	}
	return ""
}

// Router is a dns Handler which can be used to dispatch requests to different
// handler functions via configurable routes.
// Presently only IN class records are supported.
type Router struct {
	trees         map[uint16]*node
	wildcardTrees map[uint16]*node

	// Configurable dns Handler which is called when no matching route is
	// found. If it is not set, NameErrorHandler is used.
	NameError Handler

	// Function to handle panics recovered from dns handlers.
	// It should be used to generate a dns response with code 2 (SERVFAIL).
	// The handler can be used to keep your server from crashing because of
	// unrecovered panics.
	PanicHandler func(ResponseWriter, *Request, interface{})
}

// New returns a new initialized Router.
func New() *Router {
	return &Router{
		trees:         make(map[uint16]*node),
		wildcardTrees: make(map[uint16]*node),
	}
}

// Handle registers a new request handler with the given domain or RR in string.
// Only a domain that beginning with a single asterisk (*) is treated as
// wildcard (https://tools.ietf.org/html/rfc4592),
// in other cases, wild card labels are treated as same as path components used in
// httprouter (https://github.com/julienschmidt/httprouter).
// If s is a literal string which is able to create a dns.RR by dns.NewRR, the
// handler is optional and defaults to write the resulted record into answer section.
func (r *Router) Handle(s string, handler Handler) {
	if !strings.ContainsAny(s, " \t\n") {
		r.handle(dns.Fqdn(s), 0, 0, handler)
		return
	}

	record, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	if handler == nil {
		handler = Answer(record)
	}
	hdr := record.Header()
	r.handle(hdr.Name, hdr.Class, hdr.Rrtype, handler)
}

// HandleFunc registers a new request handler function with the given domain or RR in string.
func (r *Router) HandleFunc(s string, handlerFunc HandlerFunc) {
	r.Handle(s, handlerFunc)
}

func (r *Router) handle(name string, qclass, qtype uint16, handler Handler) {
	if handler == nil {
		panic(name + ": missing Handler")
	}

	trees := r.trees

	// especially, convert wild card domain to placeholder ":1" with rest of labels,
	// and insert result into the wildcardTrees
	if strings.HasPrefix(name, "*.") {
		trees = r.wildcardTrees
		name = wildcardDomainPlaceholder + name[1:]
	}

	root := trees[qclass]
	if root == nil {
		root = new(node)
		trees[qclass] = root
	}

	name = indexableString(name)
	root.addRoute(name, true, nodeHandlerElement{Qtype: qtype, Handler: handler})
}

func (r *Router) recv(w ResponseWriter, req *Request) {
	if rcv := recover(); rcv != nil {
		r.PanicHandler(w, req, rcv)
	}
}

// Lookup allows the manual lookup of a record.
// This is e.g. useful to build a framework around this router.
// If found the name, it returns the node handlers which sorted by field Qtype,
// and the name parameter values.
func (r *Router) Lookup(name string, qclass uint16) (NodeHandler, Params) {
	name = indexableString(name)

FALLBACK:
	if root := r.trees[qclass]; root != nil {
		v, params := root.getValue(name)
		if v != nil {
			return v, params
		}
	}

	if root := r.wildcardTrees[qclass]; root != nil {
		v, params := root.getValue(name)
		if v != nil {
			return v, params
		}
	}

	if qclass != 0 {
		qclass = 0
		goto FALLBACK
	}

	return nil, nil
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

// ServeDNS makes the router implement the Handler interface.
func (r *Router) ServeDNS(w ResponseWriter, req *Request) {
	if r.PanicHandler != nil {
		defer r.recv(w, req)
	}

	q := req.Question[0]
	h := r.recursiveLookup(q.Name, q.Qclass, q.Qtype)
	h = NxHandler(r, h)
	h.ServeDNS(w, req)
}

func (r *Router) recursiveLookup(name string, qclass, qtype uint16) Handler {
	nodeHandlers, params := r.Lookup(name, qclass)
	if nodeHandlers == nil {
		if r.NameError != nil {
			return r.NameError
		}
		return NameErrorHandler
	}

	if qtype == dns.TypeANY {
		return ParamsHandler(nodeHandlers, params)
	}

	var h Handler

	// firstly checks CNAME
	if cname := nodeHandlers.Search(dns.TypeCNAME); cname != nil {
		h = ParamsHandler(cname, params)
		if qtype == dns.TypeCNAME {
			return h
		}

		h = CnameHandler(r, h)
	}

	if qtype != dns.TypeCNAME {
		if h == nil {
		FALLBACK:
			h = nodeHandlers.Search(qtype)
			if h == nil {
				if qtype != 0 {
					qtype = 0
					goto FALLBACK
				}
				// no error, but no data
				return NoErrorHandler
			}
			h = ParamsHandler(h, params)
		}
		switch qtype {
		case dns.TypeNS:
			return NsHandler(r, h)
		case dns.TypeSOA:
			return SoaHandler(r, h)
		default:
			return ExtraHandler(r, h, qtype)
		}
	}

	if h != nil {
		return h
	}

	return RefusedErrorHandler
}

func indexableString(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	reverseLabels(b)
	return *(*string)(unsafe.Pointer(&b))
	//return string(b)
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
