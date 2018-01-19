package dnsrouter

import (
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

type paramContextKeyType string

const paramContextKey paramContextKeyType = "params"

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
	wildcardTrees map[uint16]*wildcardTree
	nsecNames     map[uint16]canonicalOrder
	nsec3Names    map[uint16]canonicalOrder

	// Configurable dns Handler which is called when no name found.
	// If it is not set, NameErrorHandler is used.
	NoName Handler

	// Configurable dns Handler which is called when name found along with no qtype.
	// If it is not set, NoErrorHandler is used.
	NoData Handler

	// Configurable middleware which is used when comes a query with type ANY.
	// If it is not set, defaults to output all records.
	AnyHandler Middleware
}

// Making sure the Router conforms with the Handler interface.
var _ Handler = new(Router)

// New returns a new initialized Router.
func New() *Router {
	return &Router{
		trees:         make(map[uint16]*node),
		wildcardTrees: make(map[uint16]*wildcardTree),
		nsec3Names:    make(map[uint16]canonicalOrder),
		nsecNames:     make(map[uint16]canonicalOrder),
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
		r.handle(dns.Fqdn(s), 0, 0, 0, handler)
		return
	}

	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	if handler == nil {
		handler = Answer(rr)
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

	var root tree

	if strings.HasPrefix(name, "*.") {
		n := r.wildcardTrees[qclass]
		if n == nil {
			n = new(wildcardTree)
			r.wildcardTrees[qclass] = n
		}
		root = n
	} else {
		n := r.trees[qclass]
		if n == nil {
			n = new(node)
			r.trees[qclass] = n
		}
		root = n
	}

	indexableName := newIndexableName(name)
	root.addRoute(indexableName, true, nodeHandlerElement{
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

// Lookup allows the manual lookup of a record.
// This is e.g. useful to build a framework around this router.
// If found the name, it returns the node handlers which sorted by field Qtype,
// and the name parameter values.
// Otherwise, the third boolean value indicating whether the name is a cut
// that stopping by '.' within searching path.
func (r *Router) Lookup(name string, qclass uint16) (h NodeHandler, params Params, cut bool) {
	name = newIndexableName(name)

	defer func() {
		// reverse params to against the original name
		for i, j := 0, len(params)-1; i < j; i, j = i+1, j-1 {
			params[i], params[j] = params[j], params[i]
		}
	}()

FALLBACK:
	if root := r.trees[qclass]; root != nil {
		h, params, cut = root.getValue(name)
		if h != nil || cut {
			return
		}
	}

	if root := r.wildcardTrees[qclass]; root != nil {
		h, params, cut = root.getValue(name)
		if h != nil || cut {
			return
		}
	}

	if qclass != 0 {
		qclass = 0
		goto FALLBACK
	}

	return nil, nil, false
}

// LookupNSEC looks up the previous NSEC name in canonical order.
func (r *Router) LookupNSEC(name string, qclass uint16) (NodeHandler, Params, bool) {
	if previousName := r.nsecPrevious(name, qclass, dns.TypeNSEC); previousName != "" {
		return r.Lookup(previousName, qclass)
	}
	return nil, nil, false
}

// LookupHandler performs an automated lookup of a DNS request.
func (r *Router) LookupHandler(msg *dns.Msg) Handler {
	var (
		q                         = msg.Question[0]
		qclass                    = q.Qclass
		qtype                     = q.Qtype
		opt                       = msg.IsEdns0()
		do                        = opt != nil && opt.Do()
		indexableName             = newIndexableName(q.Name)
		nodeHandlers, params, cut = r.Lookup(indexableName, qclass)
	)

	if nodeHandlers == nil {
		var h Handler

		if cut {
			// no error, but no data
			if r.NoData != nil {
				h = r.NoData
			} else {
				h = NoErrorHandler
			}
		} else {
			if r.NoName != nil {
				h = r.NoName
			} else {
				h = NameErrorHandler
			}
		}

		if do {
			h = r.NsecHandler(h)
		}

		return h
	}

	if qtype == dns.TypeANY {
		h := ParamsHandler(nodeHandlers, params)
		if r.AnyHandler != nil {
			h = r.AnyHandler(h)
		}
		return h
	}

	var rrsigHandlers, qtypeSig NodeHandler
	if do && qtype != dns.TypeRRSIG {
		rrsigHandlers = nodeHandlers.Search(dns.TypeRRSIG)
		qtypeSig = rrsigHandlers.SearchCovered(qtype)
	}

	// firstly checks CNAME for non-NSEC requests
	if qtype != dns.TypeNSEC && qtype != dns.TypeNSEC3 {
		if cname := nodeHandlers.Search(dns.TypeCNAME); cname != nil {
			h := ParamsHandler(cname, params)
			cnameSig := qtypeSig
			if qtype != dns.TypeCNAME {
				cnameSig = rrsigHandlers.SearchCovered(dns.TypeCNAME)
			}
			if cnameSig != nil {
				h = MultipleHandler(h, ParamsHandler(cnameSig, params))
			}
			// CNAME excludes all other types
			return h
		}

		if qtype == dns.TypeCNAME {
			// fallback
			qtype = 0
		}
	}

	var (
		ds, dsSig NodeHandler
		v         NodeHandler
		h         Handler

		m = make([]Handler, 0, 4)
	)

	if qtype == dns.TypeNS {
		// might be a delegation
		ds = nodeHandlers.Search(dns.TypeDS)
		dsSig = rrsigHandlers.SearchCovered(dns.TypeDS)
	}

FALLBACK:
	v = nodeHandlers.Search(qtype)
	if v == nil {
		if qtype != 0 {
			qtype = 0
			goto FALLBACK
		}

		// no error, but no data
		if r.NoData != nil {
			h = r.NoData
		} else {
			h = NoErrorHandler
		}

		if do {
			h = r.NsecHandler(h)
		}
	} else {
		h = ParamsHandler(v, params)

		// specially, there is a wildcard match
		if do && len(params) > 0 && params[0].Key == wildcardKey {
			h = r.NsecHandler(h)
		}
	}

	m = append(m, h)

	if qtypeSig != nil {
		m = append(m, ParamsHandler(qtypeSig, params))
	}
	if ds != nil {
		m = append(m, ParamsHandler(ds, params))
		if dsSig != nil {
			m = append(m, ParamsHandler(dsSig, params))
		}
	}

	return MultipleHandler(m...)
}

// NsecHandler returns a middleware that filling out denial-of-existence records.
func (r *Router) NsecHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		if req.Rcode == SkipNsecHandler {
			return
		}

		q := req.Question[0]
		result := w.Msg()

		nsecType := dns.TypeNSEC
		nodeHandler, params, _ := r.Lookup(q.Name, q.Qclass)

		if nodeHandler == nil {
			nodeHandler, params, _ = r.LookupNSEC(q.Name, q.Qclass)
		} else {
			i := first(result.Answer, q.Qtype)
			if i != -1 && isExpandable(result.Answer[0].Header().Name) {
				nodeHandler, params, _ = r.LookupNSEC(q.Name, q.Qclass)
			}
		}

		if nsecHandler := nodeHandler.Search(nsecType); nsecHandler != nil {
			nsec := FurtherRequest(w, req, q.Name, q.Qtype, ParamsHandler(nsecHandler, params))
			result.Ns = append(result.Ns, nsec.Answer...)
			if sigHandler := nodeHandler.Search(dns.TypeRRSIG).SearchCovered(nsecType); sigHandler != nil {
				sig := FurtherRequest(w, req, q.Name, q.Qtype, ParamsHandler(sigHandler, params))
				result.Ns = append(result.Ns, sig.Answer...)
			}

			if result.Rcode != dns.RcodeNameError {
				return
			}

			i := firstAny(nsec.Answer, dns.TypeNSEC3, dns.TypeNSEC)
			if i == -1 {
				return
			}

			var (
				nsecType = nsec.Answer[i].Header().Rrtype
				nsecName = nsec.Answer[i].Header().Name

				offset int
				end    bool
			)

			for !end && !strings.HasSuffix(q.Name, nsecName[offset:]) {
				offset, end = dns.NextLabel(nsecName, offset)
			}

			for !end && offset > 0 {
				nodeHandler, params, _ := r.Lookup(nsecName[offset:], q.Qclass)
				if nsecHandler := nodeHandler.Search(nsecType); nsecHandler != nil {
					nsec := FurtherRequest(w, req, q.Name, q.Qtype, ParamsHandler(nsecHandler, params))
					result.Ns = append(result.Ns, nsec.Answer...)
					if sigHandler := nodeHandler.Search(dns.TypeRRSIG).SearchCovered(nsecType); sigHandler != nil {
						sig := FurtherRequest(w, req, q.Name, q.Qtype, ParamsHandler(sigHandler, params))
						result.Ns = append(result.Ns, sig.Answer...)
					}
					break
				}

				offset, end = dns.NextLabel(nsecName, offset)
			}
		}
	})
}

// ServeDNS makes the router implement the Handler interface.
func (r *Router) ServeDNS(w ResponseWriter, req *Request) {
	r.LookupHandler(req.Msg).ServeDNS(w, req)
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
