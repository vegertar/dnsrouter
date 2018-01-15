package dnsrouter

import (
	"context"
	"errors"
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

// Param returns the value paired with the given name.
func (r *Request) Param(name string) string {
	var value string
	if v := r.Context().Value(paramContextKeyType(name)); v != nil {
		value, _ = v.(string)
	}
	return value
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

// ServeDNS implements `Handler` interface.
func (f HandlerFunc) ServeDNS(w ResponseWriter, r *Request) {
	f(w, r)
}

// Answer returns a handler which writes records into ANSWER section.
func Answer(records ...dns.RR) Handler {
	return HandlerFunc(func(w ResponseWriter, r *Request) {
		result := w.Msg()
		result.Answer = append(result.Answer, records...)
	})
}

// Ns returns a handler which writes records into AUTHORITY section.
func Ns(records ...dns.RR) Handler {
	return HandlerFunc(func(w ResponseWriter, r *Request) {
		result := w.Msg()
		result.Ns = append(result.Ns, records...)
	})
}

// Extra returns a handler which writes records into ADDITIONAL section.
func Extra(records ...dns.RR) Handler {
	return HandlerFunc(func(w ResponseWriter, r *Request) {
		result := w.Msg()
		result.Extra = append(result.Extra, records...)
	})
}

// RcodeHandler writes an arbitrary response code.
type RcodeHandler int

// ServeDNS implements `Handler` interface.
func (e RcodeHandler) ServeDNS(w ResponseWriter, r *Request) {
	w.Msg().Rcode = int(e)
}

var (
	// ErrResponseWritten resulted from writting a written response.
	ErrResponseWritten = errors.New("response has been written")

	// NoErrorHandler responses dns.RcodeSuccess.
	NoErrorHandler = RcodeHandler(dns.RcodeSuccess)

	// NameErrorHandler responses dns.RcodeNameError.
	NameErrorHandler = RcodeHandler(dns.RcodeNameError)

	// FormatErrorHandler responses dns.RcodeFormatError.
	FormatErrorHandler = RcodeHandler(dns.RcodeFormatError)

	// RefusedErrorHandler responses dns.RcodeRefused.
	RefusedErrorHandler = RcodeHandler(dns.RcodeRefused)

	// FailureErrorHandler responses dns.RcodeServerFailure.
	FailureErrorHandler = RcodeHandler(dns.RcodeServerFailure)
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
		ctx := req.Context()
		for _, item := range params {
			ctx = context.WithValue(ctx, paramContextKeyType(item.Key), item.Value)
		}
		req = req.WithContext(ctx)
		h.ServeDNS(w, req)
	})
}

// SwapDirection defines a direction of swapping two sections.
type SwapDirection int

const (
	// NsWithAnswer swapping sections between NS and ANSWER.
	NsWithAnswer SwapDirection = iota

	// NsWithExtra swapping sections between NS and ADDITIONAL.
	NsWithExtra

	// AnswerWithExtra swapping sections between ANSWER and ADDITIONAL.
	AnswerWithExtra
)

// SwapHandler swaps out sections via given directions if h serve successfully.
func SwapHandler(h Handler, directions ...SwapDirection) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		q := req.Question[0]
		msg := FurtherRequest(w, req, q.Name, q.Qtype, h)
		if msg.Rcode == dns.RcodeSuccess {
			for _, d := range directions {
				switch d {
				case NsWithAnswer:
					msg.Ns, msg.Answer = msg.Answer, msg.Ns
				case NsWithExtra:
					msg.Ns, msg.Extra = msg.Extra, msg.Ns
				case AnswerWithExtra:
					msg.Answer, msg.Extra = msg.Extra, msg.Answer
				}
			}
		}

		result := w.Msg()
		result.Answer = append(result.Answer, msg.Answer...)
		result.Ns = append(result.Ns, msg.Ns...)
		result.Extra = append(result.Extra, msg.Extra...)
	})
}

// CnameHandler is a middleware following the query on canonical name.
func CnameHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		qtype, result := req.Question[0].Qtype, w.Msg()
		if qtype == dns.TypeCNAME {
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

			cnameWriter := FurtherRequest(w, req, cname, qtype, h)
			result.Rcode = cnameWriter.Rcode
			result.Answer = append(result.Answer, cnameWriter.Answer...)
			answer = cnameWriter.Answer
		}
	})
}

// ExtraHandler is a middleware filling out additional A/AAAA records for target names.
func ExtraHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		if result := w.Msg(); len(result.Extra) == 0 && len(result.Answer) > 0 {
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

				for _, t := range aReqTypes {
					extraWriter := FurtherRequest(w, req, target, t, h)
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

// NsecHandler is a middleware filling out denial-of-existence records.
func NsecHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		q := req.Question[0]
		result := w.Msg()

		if exists(result.Answer, q.Qtype) {
			return
		}

		if opt := req.IsEdns0(); opt == nil || !opt.Do() {
			return
		}

		var (
			nsecName string
			nsecType uint16
		)

		if nsec3 := FurtherRequest(w, req, q.Name, dns.TypeNSEC3, h); len(nsec3.Answer) > 0 {
			nsecName = nsec3.Answer[0].Header().Name
			nsecType = dns.TypeNSEC3
			result.Ns = append(result.Ns, nsec3.Answer...)
		} else if nsec := FurtherRequest(w, req, q.Name, dns.TypeNSEC, h); len(nsec.Answer) > 0 {
			nsecName = nsec.Answer[0].Header().Name
			nsecType = dns.TypeNSEC
			result.Ns = append(result.Ns, nsec.Answer...)
		} else {
			return
		}

		if result.Rcode != dns.RcodeNameError {
			return
		}

		var nsec dns.Msg
		closestName := nsecName

		for !strings.HasSuffix(q.Name, closestName) {
			if i := strings.Index(closestName, "."); i != -1 {
				closestName = closestName[i+1:]
			} else {
				break
			}

			nsec = FurtherRequest(w, req, closestName, nsecType, h)
			if len(nsec.Answer) > 0 {
				closestName = nsec.Answer[0].Header().Name
			}
			if closestName == nsecName {
				break
			}
		}
		if closestName != nsecName && strings.HasSuffix(q.Name, closestName) {
			result.Ns = append(result.Ns, nsec.Answer...)
		}
	})
}

// NxHandler is a middleware filling out a SOA record if occurs NXDOMAIN or NOERROR with no data,
// as well as filling out NS records for non-NS queries. The authoritative field will be set
// appropriately depending whether the requested owner name is delegated or not.
func NxHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		var (
			qtype  = req.Question[0].Qtype
			qname  = req.Question[0].Name
			result = w.Msg()
			offset = 0
			rcode  = result.Rcode
			answer = result.Answer
		)

		if rcode != dns.RcodeNameError && rcode != dns.RcodeSuccess ||
			existsAny(result.Ns, dns.TypeNS, dns.TypeSOA) {
			return
		}

		if i := firstNotAny(answer,
			dns.TypeCNAME,
			dns.TypeRRSIG,
			dns.TypeNSEC,
			dns.TypeNSEC3,
		); i != -1 {
			qname, answer = answer[i].Header().Name, answer[i:]
		}

		var (
			ns, soa dns.Msg
			hasData bool
		)

		defer func() {
			result.Authoritative = true
			if len(soa.Answer) == 0 {
				// delegated
				result.Authoritative = false
				if qtype != dns.TypeDS {
					result.Answer = nil
				}
				result.Ns = ns.Answer
				result.Extra = ns.Extra
				if result.Rcode == dns.RcodeNameError {
					result.Rcode = dns.RcodeSuccess
				}
			} else if hasData {
				if qtype != dns.TypeNS {
					result.Ns = append(result.Ns, ns.Answer...)
					result.Extra = append(result.Extra, ns.Extra...)
				}
			} else {
				result.Ns = append(result.Ns, soa.Answer...)
				result.Extra = append(result.Extra, soa.Extra...)
			}
		}()

		if i := first(answer, qtype); i != -1 {
			hasData = true
			if qtype == dns.TypeNS {
				ns.Answer, ns.Extra = result.Answer, result.Extra
				if m := FurtherRequest(w, req, qname, dns.TypeSOA, h); exists(m.Answer, dns.TypeSOA) {
					soa = m
				}
				return
			}
		}

		if nsOwner, soaOwner := apexFromNsec(result.Ns); nsOwner != "" || soaOwner != "" {
			if nsOwner != soaOwner && len(nsOwner) > len(soaOwner) {
				ns = FurtherRequest(w, req, nsOwner, dns.TypeNS, h)
			} else if !hasData {
				soa = FurtherRequest(w, req, soaOwner, dns.TypeSOA, h)
			}

			return
		}

		for i, end := 0, false; !end && len(ns.Answer) == 0; i++ {
			if rcode == dns.RcodeNameError || // directly go up when NXDOMAIN
				hasData && qtype == dns.TypeDS || // always go up for delegation
				i > 0 { // go up from 2nd iteration when NOERROR but no data
				offset, end = dns.NextLabel(qname, offset)
			}

			if !end {
				name := qname[offset:]
				if len(ns.Answer) == 0 {
					m := FurtherRequest(w, req, name, dns.TypeNS, h)
					if m.Rcode == dns.RcodeNameError {
						continue
					}
					if exists(m.Answer, dns.TypeNS) {
						ns = m
					}
				}
				if len(soa.Answer) == 0 {
					m := FurtherRequest(w, req, name, dns.TypeSOA, h)
					if m.Rcode == dns.RcodeNameError {
						continue
					}
					if exists(m.Answer, dns.TypeSOA) {
						soa = m
					}
				}
			}
		}
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
		if len(result.Answer) == 0 && len(result.Ns) == 0 && result.Rcode == dns.RcodeSuccess {
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
				txt.Hdr.Name = "panic." + req.Question[0].Name
				txt.Hdr.Class = req.Question[0].Qclass
				txt.Hdr.Rrtype = dns.TypeTXT
				txt.Txt = []string{fmt.Sprint(v), identifyPanic()}

				result := w.Msg()
				result.Rcode = dns.RcodeServerFailure
				result.Extra = append(result.Extra, txt)
			}
		}()

		h.ServeDNS(w, req)
	})
}

// LoggingHandler is a middleware logging requests.
func LoggingHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		defer func() {
			// TODO:
		}()

		h.ServeDNS(w, req)
	})
}

// MultipleHandler merges multiple handlers into a single one.
func MultipleHandler(m ...Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		for _, h := range m {
			if h != nil {
				h.ServeDNS(w, req)
			}
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

// Classic returns a github.com/miekg/dns.Handler.
// If middlewares is nil, then use DefaultLoggingScheme.
func Classic(ctx context.Context, h Handler, middlewares ...Middleware) dns.Handler {
	if middlewares == nil {
		middlewares = DefaultLoggingScheme
	}
	h = ChainHandler(h, middlewares...)

	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := NewResponseWriter()
		req := &Request{Msg: r, ctx: ctx}
		h.ServeDNS(resp, req)
		if err := w.WriteMsg(resp.Msg().SetReply(r)); err != nil {
			log.Println("dns.WriteMsg error:", err)
		}
	})
}

var (
	// DefaultScheme consists of essential middlewares.
	DefaultScheme = []Middleware{
		PanicHandler,
		RefusedHandler,
		OptHandler,
		NxHandler,
		NsecHandler,
		ExtraHandler,
		CnameHandler,
	}

	// DefaultLoggingScheme consists of LoggingHandler and DefaultScheme.
	DefaultLoggingScheme = append([]Middleware{LoggingHandler}, DefaultScheme...)
)

func exists(rrSet []dns.RR, t uint16) bool {
	return first(rrSet, t) != -1
}

func existsAny(rrSet []dns.RR, t ...uint16) bool {
	return firstAny(rrSet, t...) != -1
}

func first(rrSet []dns.RR, t uint16) int {
	for i, rr := range rrSet {
		if rr.Header().Rrtype == t {
			return i
		}
	}
	return -1
}

func last(rrSet []dns.RR, t uint16) int {
	for i := len(rrSet) - 1; i >= 0; i-- {
		if rrSet[i].Header().Rrtype == t {
			return i
		}
	}
	return -1
}

func firstAny(rrSet []dns.RR, t ...uint16) int {
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

func firstNotAny(rrSet []dns.RR, t ...uint16) int {
	for i, rr := range rrSet {
		rrType := rr.Header().Rrtype
		not := true
		for _, j := range t {
			if j == rrType {
				not = false
				break
			}
		}
		if not {
			return i
		}
	}
	return -1
}

func apexFromNsec(rrSet []dns.RR) (nsOwner, soaOwner string) {
	for _, rr := range rrSet {
		switch rr.Header().Rrtype {
		case dns.TypeNSEC:
			nsec := rr.(*dns.NSEC)
			for _, b := range nsec.TypeBitMap {
				if nsOwner != "" && soaOwner != "" {
					return
				}
				switch b {
				case dns.TypeNS:
					if nsOwner == "" {
						nsOwner = nsec.Header().Name
					}
				case dns.TypeSOA:
					if soaOwner == "" {
						soaOwner = nsec.Header().Name
					}
				}
			}
		case dns.TypeNSEC3:
			// TODO: supports NSEC3
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
