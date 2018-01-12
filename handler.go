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
	aTypes = []uint16{dns.TypeA, dns.TypeAAAA}
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
			answer = cnameWriter.Answer

			result.Rcode = cnameWriter.Rcode
			result.Answer = append(result.Answer, cnameWriter.Answer...)
		}
	})
}

// NsHandler is a middleware filling out the glue records.
func NsHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		if result := w.Msg(); result.Rcode == dns.RcodeSuccess && len(result.Answer) > 0 {
			delegated := false
			noData := true

			for _, rr := range result.Answer {
				if rr.Header().Rrtype != dns.TypeNS {
					continue
				}

				noData = false
				ns := rr.(*dns.NS).Ns
				if strings.HasSuffix(ns, rr.Header().Name) {
					delegated = true
				}

				for _, t := range aTypes {
					glueWriter := FurtherRequest(w, req, ns, t, h)
					if glueWriter.Rcode == dns.RcodeNameError {
						break
					}

					result.Extra = append(result.Extra, glueWriter.Answer...)
				}
			}

			if !noData {
				result.Authoritative = true

				if delegated {
					result.Answer, result.Ns = result.Ns, result.Answer
					result.Authoritative = false
				}
			}
		}
	})
}

// SoaHandler is a middleware setting authoritative bit.
func SoaHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		if result := w.Msg(); exists(result.Answer, dns.TypeSOA) {
			result.Authoritative = true
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
				default:
					continue
				}

				for _, t := range aTypes {
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

// NxHandler is a middleware filling out a SOA record if occurs NXDOMAIN or NOERROR with no data,
// as well as filling out NS records for non-NS queries.
func NxHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		var (
			msg dns.Msg

			qtype       = req.Question[0].Qtype
			qname       = req.Question[0].Name
			result      = w.Msg()
			offset      = 0
			rcode       = result.Rcode
			answer      = result.Answer
			targetQtype = dns.TypeSOA
			noData      = true
		)

		if qtype == dns.TypeNSEC || qtype == dns.TypeNSEC3 {
			return
		}

		if !(rcode == dns.RcodeNameError ||
			rcode == dns.RcodeSuccess && !exists(answer, qtype)) {
			switch qtype {
			case dns.TypeNS:
				return
			case dns.TypeCNAME:
				if i := last(answer, dns.TypeCNAME); i != -1 {
					qname, answer = answer[i].(*dns.CNAME).Target, answer[i+1:]
				}
			default:
				if i := firstNotAny(answer,
					dns.TypeCNAME,
					dns.TypeRRSIG,
					dns.TypeNSEC,
					dns.TypeNSEC3,
				); i != -1 {
					qname, answer = answer[i].Header().Name, answer[i:]
				}
			}
			targetQtype = dns.TypeNS
		}

		for {
			ok := false
			if rcode == dns.RcodeNameError {
				offset, _ = dns.NextLabel(qname, offset)
				ok = true
			} else if rcode == dns.RcodeSuccess {
				if noData = !exists(answer, targetQtype); noData {
					if qtype == targetQtype {
						offset, _ = dns.NextLabel(qname, offset)
					} else {
						qtype = targetQtype
					}
					ok = true
				}
			}

			if !ok || offset >= len(qname) {
				break
			}

			msg = FurtherRequest(w, req, qname[offset:], targetQtype, h)
			rcode, answer = msg.Rcode, msg.Answer
		}

		if !noData {
			if msg.Authoritative {
				result.Authoritative = true
			}
			result.Ns = append(result.Ns, msg.Answer...)
			result.Extra = append(result.Extra, msg.Extra...)
		}
	})
}

// NsecHandler is a middleware filling out denial-of-existence records.
func NsecHandler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		q := req.Question[0]
		result := w.Msg()

		if !(result.Rcode == dns.RcodeNameError ||
			result.Rcode == dns.RcodeSuccess && !exists(result.Answer, q.Qtype)) {
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
		OptHandler,
		NsecHandler,
		NxHandler,
		ExtraHandler,
		CnameHandler,
	}

	// DefaultLoggingScheme consists of LoggingHandler and DefaultScheme.
	DefaultLoggingScheme = append([]Middleware{LoggingHandler}, DefaultScheme...)
)

func exists(rrSet []dns.RR, t uint16) bool {
	return first(rrSet, t) != -1
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
