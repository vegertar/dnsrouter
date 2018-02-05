package dnsrouter

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"strings"

	"github.com/miekg/dns"
)

// Middleware is a piece of middleware.
type Middleware func(Handler) Handler

// A ResponseWriter interface is used by a DNS handler to construct an DNS response.
type ResponseWriter interface {
	Msg() *dns.Msg
}

type responseWriter struct {
	msg dns.Msg
}

func (p *responseWriter) Msg() *dns.Msg {
	return &p.msg
}

// NewResponseWriter creates a response writer.
func NewResponseWriter() ResponseWriter {
	return new(responseWriter)
}

// A Request represents a DNS request received by a server.
type Request struct {
	*dns.Msg

	ctx context.Context
}

// Params returns the binding params.
func (r *Request) Params() Params {
	if v := r.Context().Value(paramContextKey); v != nil {
		return v.(Params)
	}
	return nil
}

// Context returns the request's context. To change the context, use WithContext.
func (r *Request) Context() context.Context {
	if r.ctx != nil {
		return r.ctx
	}
	return context.Background()
}

// WithContext returns a shallow copy of r with its context changed to ctx.
// The provided ctx must be non-nil.
func (r *Request) WithContext(ctx context.Context) *Request {
	if ctx == nil {
		panic("nil context")
	}
	r2 := new(Request)
	*r2 = *r
	r2.ctx = ctx
	return r2
}

// NewRequest makes a question request.
func NewRequest(qname string, qtype uint16) *Request {
	msg := new(dns.Msg)
	msg.SetQuestion(qname, qtype)
	return &Request{Msg: msg}
}

// A Handler responds to a DNS request.
type Handler interface {
	ServeDNS(ResponseWriter, *Request)
}

// The HandlerFunc type is an adapter to allow the use of ordinary functions as DNS handlers.
type HandlerFunc func(ResponseWriter, *Request)

// ServeDNS implements Handler interface.
func (f HandlerFunc) ServeDNS(w ResponseWriter, r *Request) {
	f(w, r)
}

// Answer is a handler which writes the RR into ANSWER section.
type Answer struct {
	dns.RR
}

// ServeDNS implements Handler interface.
func (a Answer) ServeDNS(w ResponseWriter, r *Request) {
	result := w.Msg()
	result.Answer = append(result.Answer, a.RR)
}

// RcodeHandler writes an arbitrary response code.
type RcodeHandler int

// ServeDNS implements Handler interface.
func (e RcodeHandler) ServeDNS(w ResponseWriter, r *Request) {
	w.Msg().Rcode = int(e)
}

var (
	// NoErrorHandler responses dns.RcodeSuccess.
	NoErrorHandler = RcodeHandler(dns.RcodeSuccess)

	// NameErrorHandler responses dns.RcodeNameError.
	NameErrorHandler = RcodeHandler(dns.RcodeNameError)
)

var (
	aReqTypes = []uint16{dns.TypeA, dns.TypeAAAA}
)

// ParamsHandler fills the params into request context.
func ParamsHandler(h Handler, params Params) Handler {
	if params == nil {
		return h
	}
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		ctx := context.WithValue(req.Context(), paramContextKey, params)
		h.ServeDNS(w, req.WithContext(ctx))
	})
}

// BasicHandler is a middleware filling out essential answer section.
func BasicHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		result := w.Msg()
		if result.Rcode != dns.RcodeSuccess {
			return
		}

		qtype := req.Question[0].Qtype
		if ExistsAny(result.Answer, dns.TypeCNAME, qtype) ||
			qtype == dns.TypeANY && len(result.Answer) > 0 {
			return
		}

		var class, rrsig Class

		if classValue := req.Context().Value(ClassContextKey); classValue != nil {
			class = classValue.(Class)
		} else {
			return
		}

		if opt := req.IsEdns0(); opt != nil && opt.Do() {
			if qtype != dns.TypeRRSIG && qtype != dns.TypeANY {
				if v, ok := class.Search(dns.TypeRRSIG).(Class); ok {
					rrsig = v
				}
			}
		}

		h := class.Search(qtype)
		if rrsig != nil {
			if t, ok := h.(CheckRedirect); ok {
				qtype = t.Qtype()
			}
			sig := rrsig.Search(qtype)
			if sig != nil {
				h = MultiHandler(h, sig)
			}
		}

		h.ServeDNS(w, req)
	})
}

// CnameHandler is a middleware following the query on canonical name.
func CnameHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		var (
			qname  = req.Question[0].Name
			qtype  = req.Question[0].Qtype
			result = w.Msg()
		)

		if i := First(result.Answer, dns.TypeDNAME); i != -1 {
			dname := result.Answer[i].(*dns.DNAME)
			owner := dname.Hdr.Name
			diff := len(qname) - len(owner)
			if diff > 0 && dns.IsSubDomain(owner, qname) {
				cname := new(dns.CNAME)
				cname.Hdr = dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    dname.Hdr.Ttl,
				}
				cname.Target = qname[:diff] + dname.Target
				result.Answer = append(result.Answer, cname)
			}
		}

		if qtype == dns.TypeCNAME || qtype == dns.TypeANY {
			return
		}

		var stub Stub
		if classValue := req.Context().Value(ClassContextKey); classValue != nil {
			stub = classValue.(Class).Stub()
		}
		if stub == nil {
			return
		}

		answer := result.Answer

		for {
			var cname string
			for _, rr := range answer {
				if rr.Header().Rrtype == dns.TypeCNAME {
					cname = rr.(*dns.CNAME).Target
					break
				}
			}
			if cname == "" {
				break
			}

			class := stub.Lookup(cname, req.Question[0].Qclass)
			if _, ok := class.Search(dns.TypeANY).(RcodeHandler); ok {
				break
			}

			ctx := context.WithValue(req.Context(), ClassContextKey, class)
			cnameWriter := FurtherRequest(w, req.WithContext(ctx), cname, qtype, WildcardHandler(h))
			result.Answer = append(result.Answer, cnameWriter.Answer...)
			answer = cnameWriter.Answer
		}
	})
}

// ExtraHandler is a middleware filling out additional A/AAAA records for target names.
func ExtraHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		if req.Question[0].Qtype == dns.TypeANY {
			return
		}

		if result := w.Msg(); len(result.Extra) == 0 && len(result.Answer) > 0 {
			var stub Stub
			if classValue := req.Context().Value(ClassContextKey); classValue != nil {
				stub = classValue.(Class).Stub()
			}
			if stub == nil {
				return
			}

			for _, rr := range result.Answer {
				var target string
				switch rr.Header().Rrtype {
				case dns.TypeSRV:
					target = rr.(*dns.SRV).Target
				case dns.TypeMX:
					target = rr.(*dns.MX).Mx
				case dns.TypeNS:
					target = rr.(*dns.NS).Ns
				default:
					continue
				}

				class := stub.Lookup(target, req.Question[0].Qclass)
				if _, ok := class.Search(dns.TypeANY).(RcodeHandler); ok {
					continue
				}

				ctx := context.WithValue(req.Context(), ClassContextKey, class)
				extraReq := req.WithContext(ctx)

				for _, t := range aReqTypes {
					extraWriter := FurtherRequest(w, extraReq, target, t, WildcardHandler(h))
					if extraWriter.Rcode == dns.RcodeNameError {
						break
					}

					result.Extra = append(result.Extra, extraWriter.Answer...)
					result.Extra = append(result.Extra, extraWriter.Extra...)
				}
			}
		}
	})
}

// NsHandler returns a middleware that filling out NS section.
func NsHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		var (
			qtype  = req.Question[0].Qtype
			result = w.Msg()
		)

		if qtype == dns.TypeANY ||
			result.Rcode != dns.RcodeNameError && result.Rcode != dns.RcodeSuccess ||
			ExistsAny(result.Ns, dns.TypeNS, dns.TypeSOA) {
			return
		}

		hasData := ExistsAny(result.Answer, qtype, dns.TypeCNAME)

		var class Class
		if classValue := req.Context().Value(ClassContextKey); classValue != nil {
			class = classValue.(Class)
		} else {
			return
		}

		if zone, delegated := class.Zone(); zone != nil {
			if delegated {
				result.Authoritative = false
				if hasData && qtype == dns.TypeNS {
					result.Answer, result.Ns = result.Ns, result.Answer

					// adding DS records
					if opt := req.IsEdns0(); opt != nil && opt.Do() {
						ctx := context.WithValue(req.Context(), ClassContextKey, zone)
						m := FurtherRequest(w, req.WithContext(ctx), req.Question[0].Name, dns.TypeDS, WildcardHandler(h))
						result.Ns = append(result.Ns, m.Answer...)
					}
					return
				}

				// clears data for delegation except DS
				if hasData {
					if qtype != dns.TypeDS {
						result.Answer = nil
						hasData = false
					} else {
						// upgrading zone
						dsZone, _ := zone.Zone()
						if dsZone == nil {
							return
						}
						zone = dsZone
						delegated = true
					}
				}
			} else {
				result.Authoritative = true

				if hasData && qtype == dns.TypeNS {
					return
				}
			}

			var nsType uint16

			if hasData || delegated {
				nsType = dns.TypeNS
				result.Rcode = dns.RcodeSuccess
			} else {
				nsType = dns.TypeSOA
			}

			ctx := context.WithValue(req.Context(), ClassContextKey, zone)
			m := FurtherRequest(w, req.WithContext(ctx), req.Question[0].Name, nsType, WildcardHandler(h))
			result.Ns = append(result.Ns, m.Answer...)
			result.Extra = append(result.Extra, m.Extra...)

			// adding DS records
			if delegated && !hasData {
				if opt := req.IsEdns0(); opt != nil && opt.Do() {
					m := FurtherRequest(w, req.WithContext(ctx), req.Question[0].Name, dns.TypeDS, WildcardHandler(h))
					result.Ns = append(result.Ns, m.Answer...)
				}
			}
		}
	})
}

// NsecHandler returns a middleware that filling out denial-of-existence records.
func NsecHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		if req.Question[0].Qtype == dns.TypeANY {
			return
		}

		if opt := req.IsEdns0(); opt == nil || !opt.Do() {
			return
		}

		result := w.Msg()
		if ExistsAny(result.Ns, dns.TypeNSEC, dns.TypeNSEC3) {
			return
		}

		var class, nextSecure Class

		if classValue := req.Context().Value(ClassContextKey); classValue != nil {
			class = classValue.(Class)
		} else {
			return
		}

		zone, delegated := class.Zone()
		if zone == nil {
			return
		}

		if delegated && Exists(result.Ns, dns.TypeNS) {
			return
		}

		var nsecType = dns.TypeNSEC

		if i := FirstAny(result.Answer, dns.TypeCNAME, req.Question[0].Qtype); i != -1 {
			if strings.HasPrefix(result.Answer[i].Header().Name, "*.") {
				nextSecure = class.NextSecure(nsecType)
			}
		} else if result.Rcode == dns.RcodeNameError {
			nextSecure = class.NextSecure(nsecType)
		} else if result.Rcode == dns.RcodeSuccess {
			if _, ok := class.Search(dns.TypeANY).(RcodeHandler); ok {
				nextSecure = class.NextSecure(nsecType)
			} else {
				nextSecure = class
			}
		}

		if nextSecure == nil {
			return
		}

		var nsec, nsecSig Handler

		nsec = nextSecure.Search(nsecType)
		if nsecRrsig, ok := nextSecure.Search(dns.TypeRRSIG).(Class); ok {
			nsecSig = nsecRrsig.Search(nsecType)
		}

		m := FurtherRequest(w, req, req.Question[0].Name, nsecType, MultiHandler(nsec, nsecSig))
		result.Ns = append(result.Ns, m.Answer...)

		if result.Rcode != dns.RcodeNameError {
			return
		}

		i := First(m.Answer, nsecType)
		if i == -1 {
			return
		}

		if dns.IsSubDomain(m.Answer[i].Header().Name, req.Question[0].Name) {
			return
		}

		var zoneNsec, zoneNsecSig Handler

		zoneNsec = zone.Search(nsecType)
		if zoneRrsig, ok := zone.Search(dns.TypeRRSIG).(Class); ok {
			zoneNsecSig = zoneRrsig.Search(nsecType)
		}

		m = FurtherRequest(w, req, req.Question[0].Name, nsecType, MultiHandler(zoneNsec, zoneNsecSig))
		result.Ns = append(result.Ns, m.Answer...)
	})
}

// WildcardHandler is a middleware expanding wildcard.
func WildcardHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		if req.Question[0].Qtype == dns.TypeANY {
			return
		}

		expandWildcard(w.Msg().Answer, req.Question[0].Name, req.Question[0].Qtype)
	})
}

// OptHandler is a middleware filling out OPT records if request is compatible with EDNS0.
func OptHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		if opt := req.IsEdns0(); opt != nil {
			result := w.Msg()
			if resultOpt := result.IsEdns0(); resultOpt != nil {
				return
			}

			resultOpt := *opt
			resultOpt.Hdr.Name = "."
			resultOpt.Hdr.Rrtype = dns.TypeOPT
			resultOpt.SetVersion(0)
			resultOpt.SetUDPSize(opt.UDPSize())
			resultOpt.Hdr.Ttl &= 0xff00 // clear flags

			if opt.Do() {
				resultOpt.SetDo()
			}
			result.Extra = append(result.Extra, &resultOpt)
		}
	})
}

// RefusedHandler is a middleware setting REFUSED code if no ANSWERs or NSs either.
func RefusedHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		result := w.Msg()
		if len(result.Answer) == 0 && len(result.Ns) == 0 && result.Rcode == dns.RcodeNameError {
			result.Rcode = dns.RcodeRefused
		}
	})
}

// PanicHandler is a middleware filling out an extra TXT record from a recovered panic,
// as well as setting SERVFAIL.
func PanicHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		defer func() {
			if v := recover(); v != nil {
				txt := new(dns.TXT)
				txt.Hdr.Name = req.Question[0].Name
				txt.Hdr.Class = req.Question[0].Qclass
				txt.Hdr.Rrtype = dns.TypeTXT
				txt.Txt = []string{"panic", fmt.Sprint(v), identifyPanic()}

				result := w.Msg()
				result.Rcode = dns.RcodeServerFailure
				result.Extra = append(result.Extra, txt)
			}
		}()

		h.ServeDNS(w, req)
	})
}

// MultiHandler merges multiple handlers into a single one.
func MultiHandler(m ...Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		for _, h := range m {
			if h != nil {
				h.ServeDNS(w, req)
			}
		}
	})
}

// FurtherRequest is a helper function to execute another query within current context.
func FurtherRequest(w ResponseWriter, req *Request, qname string, qtype uint16, h Handler) dns.Msg {
	rawW := *w.Msg()
	rawName, rawType := req.Question[0].Name, req.Question[0].Qtype

	defer func() {
		*w.Msg() = rawW
		req.Question[0].Name = rawName
		req.Question[0].Qtype = rawType
	}()

	*w.Msg() = dns.Msg{}
	req.Question[0].Name = qname
	req.Question[0].Qtype = qtype
	h.ServeDNS(w, req)
	return *w.Msg()
}

// Classic converts a Handler into the github.com/miekg/dns.Handler.
func Classic(ctx context.Context, h Handler) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := NewResponseWriter()
		req := &Request{Msg: r, ctx: ctx}
		h.ServeDNS(resp, req)

		msg := resp.Msg()
		rcode := msg.Rcode
		msg = msg.SetReply(r)
		msg.Rcode = rcode

		if err := w.WriteMsg(msg); err != nil {
			log.Println("dns.WriteMsg error:", err)
		}
	})
}

// ChainHandler applies middlewares on given handler.
func ChainHandler(h Handler, middlewares ...Middleware) Handler {
	for i, n := 0, len(middlewares); i < n; i++ {
		h = middlewares[n-i-1](h)
	}
	return h
}

var (
	// DefaultScheme consists of middlewares serving as a complete stub name server.
	DefaultScheme = []Middleware{
		PanicHandler,
		RefusedHandler,
		OptHandler,
		WildcardHandler,
		NsecHandler,
		NsHandler,
		ExtraHandler,
		CnameHandler,
		BasicHandler,
	}

	// SimpleScheme consists of essential middlewares without filling out AUTHORITY and ADDITIONAL sections.
	// This scheme is faster (2x bench of DefaultScheme) and suitable for most of ordinary situations.
	SimpleScheme = []Middleware{
		PanicHandler,
		RefusedHandler,
		OptHandler,
		WildcardHandler,
		CnameHandler,
		BasicHandler,
	}
)

// Exists checks if a given qtype exists.
func Exists(rrSet []dns.RR, t uint16) bool {
	return First(rrSet, t) != -1
}

// ExistsAny checks if any of given qtypes exists.
func ExistsAny(rrSet []dns.RR, t ...uint16) bool {
	return FirstAny(rrSet, t...) != -1
}

// First returns the index of the first element of given qtype.
// If not found, returns -1.
func First(rrSet []dns.RR, t uint16) int {
	for i, rr := range rrSet {
		if rr.Header().Rrtype == t {
			return i
		}
	}
	return -1
}

// FirstAny returns the index of the first element of any of given qtypes.
// If not found, returns -1.
func FirstAny(rrSet []dns.RR, t ...uint16) int {
	for i, rr := range rrSet {
		rrType := rr.Header().Rrtype
		for _, j := range t {
			if j == rrType {
				return i
			}
		}
	}
	return -1
}

func expandWildcard(rrSet []dns.RR, qname string, qtype uint16) (wildcardName string) {
	var expanded, expandedCname bool

	for i, rr := range rrSet {
		h := rr.Header()
		if !strings.HasPrefix(h.Name, "*.") {
			continue
		}

		if h.Rrtype == qtype {
			expanded = true
		} else if h.Rrtype == dns.TypeCNAME {
			expandedCname = true
		} else if h.Rrtype == dns.TypeRRSIG {
			rrsig := rr.(*dns.RRSIG)
			if rrsig.TypeCovered == qtype {
				expanded = true
			} else if rrsig.TypeCovered == dns.TypeCNAME {
				expandedCname = true
			}
		}

		if expanded && expandedCname {
			panic(h.Name + ": confusing expansion with CNAME")
		}

		if expanded || expandedCname {
			if wildcardName != "" && rr.Header().Name != wildcardName {
				panic(fmt.Sprintf(`wildcard name "%s" conflicting with previous one: %s`,
					rr.Header().Name, wildcardName))
			}
			wildcardName = rr.Header().Name
			rr = dns.Copy(rr)
			rr.Header().Name = qname
			rrSet[i] = rr
		}
	}

	return
}

// see https://gist.github.com/swdunlop/9629168
func identifyPanic() string {
	var name, file string
	var line int
	var pc [16]uintptr

	n := runtime.Callers(3, pc[:])
	for _, pc := range pc[:n] {
		fn := runtime.FuncForPC(pc)
		if fn == nil {
			continue
		}
		file, line = fn.FileLine(pc)
		name = fn.Name()
		if !strings.HasPrefix(name, "runtime.") {
			break
		}
	}

	switch {
	case name != "":
		return fmt.Sprintf("%v:%v", name, line)
	case file != "":
		return fmt.Sprintf("%v:%v", file, line)
	}

	return fmt.Sprintf("pc:%x", pc)
}
