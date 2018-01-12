package dnsrouter

import (
	"io"
	"os"
	"path"
	"sort"
	"strings"

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
	nsecNames     map[uint16]canonicalOrder
	nsec3Names    map[uint16]canonicalOrder

	// Configurable dns Handler which is called when no name found.
	// If it is not set, NameErrorHandler is used.
	NoName Handler

	// Configurable dns Handler which is called when name found along with no qtype.
	// If it is not set, NoErrorHandler is used.
	NoData Handler

	// Configurable middleware which is used when comes a query with type ANY.
	AnyHandler Middleware
}

// Making sure the Router conforms with the Handler interface.
var _ Handler = new(Router)

// New returns a new initialized Router.
func New() *Router {
	return &Router{
		trees:         make(map[uint16]*node),
		wildcardTrees: make(map[uint16]*node),
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

func (r *Router) handle(name string, qclass, qtype, typeCovered uint16, handler Handler) {
	if name == "" || len(name) > 1 && isIndexable(name) {
		panic(name + ": illegal domain")
	}
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

	indexableName := IndexableName(name)
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

// nsecPrevious returns the previous routing item by canonical order,
// and found indicating whether the original name is existed.
func (r *Router) nsecPrevious(name string, qclass, qtype uint16) (indexableName string, found bool) {
	switch qtype {
	case dns.TypeNSEC3:
		if r.nsec3Names != nil {
			return r.nsec3Names[qclass].Previous(IndexableName(name))
		}
	case dns.TypeNSEC:
		if r.nsecNames != nil {
			return r.nsecNames[qclass].Previous(IndexableName(name))
		}
	}
	return
}

// Lookup allows the manual lookup of a record.
// This is e.g. useful to build a framework around this router.
// If found the name, it returns the node handlers which sorted by field Qtype,
// and the name parameter values.
func (r *Router) Lookup(name string, qclass uint16) (NodeHandler, Params) {
	name = IndexableName(name)

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

// LookupNSEC performs like Lookup whereas with parameter qtype
// which is either dns.TypeNSEC or dns.TypeNSEC3.
func (r *Router) LookupNSEC(name string, qclass, qtype uint16) (NodeHandler, Params) {
	// TODO: supports NSEC3
	name = IndexableName(name)
	if previousName, found := r.nsecPrevious(name, qclass, qtype); previousName != "" {
		if !found {
			name = previousName
		}
		return r.Lookup(name, qclass)
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
	q := req.Question[0]
	h := r.lookupHandler(dns.Fqdn(q.Name), q.Qclass, q.Qtype, req.IsEdns0())
	h.ServeDNS(w, req)
}

func (r *Router) lookupHandler(name string, qclass, qtype uint16, opt *dns.OPT) (h Handler) {
	do := opt != nil && opt.Do()
	indexableName := IndexableName(name)

	var (
		nodeHandlers NodeHandler
		params       Params
		isNsec       bool
	)

	if qtype == dns.TypeNSEC || qtype == dns.TypeNSEC3 {
		isNsec = true
		nodeHandlers, params = r.LookupNSEC(indexableName, qclass, qtype)
	} else {
		nodeHandlers, params = r.Lookup(indexableName, qclass)
	}

	if nodeHandlers == nil {
		if r.NoName != nil {
			h = r.NoName
		} else {
			h = NameErrorHandler
		}

		return h
	}

	if qtype == dns.TypeANY {
		h = ParamsHandler(nodeHandlers, params)
		if r.AnyHandler != nil {
			h = r.AnyHandler(h)
		}
		return h
	}

	var rrsigHandlers NodeHandler
	if do && qtype != dns.TypeRRSIG {
		rrsigHandlers = nodeHandlers.Search(dns.TypeRRSIG)
	}

	// firstly checks CNAME for non-NSEC requests
	if !isNsec {
		if cname := nodeHandlers.Search(dns.TypeCNAME); cname != nil {
			h = ParamsHandler(cname, params)
			if cnameSIG := rrsigHandlers.SearchCovered(dns.TypeCNAME); cnameSIG != nil {
				h = MultipleHandler(h, ParamsHandler(cnameSIG, params))
			}
			if qtype == dns.TypeCNAME {
				return h
			}
		}
	}

	if qtype != dns.TypeCNAME {
		qtypeSig := rrsigHandlers.SearchCovered(qtype)

		if h == nil {
			var v NodeHandler

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

				return h
			}

			h = ParamsHandler(v, params)
		}

		if qtypeSig != nil {
			h = MultipleHandler(h, ParamsHandler(qtypeSig, params))
		}
	}

	if h != nil {
		return h
	}

	return RefusedErrorHandler
}

// IndexableName returns a name for indexing.
func IndexableName(name string) string {
	if !isIndexable(name) {
		name = indexableString(dns.Fqdn(name))
	}
	return name
}

// UnindexableName reverts indexable name to original name.
func UnindexableName(name string) string {
	if isIndexable(name) {
		// reversing again
		name = indexableString(name)
	}
	return name
}

func isIndexable(s string) bool {
	return s != "" && s[0] == '.'
}

func indexableString(s string) string {
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
			if len(xI) > 1 && yI[0] == '*' {
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
	return x < y
}
