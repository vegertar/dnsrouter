package dnsrouter

import (
	"context"
	"errors"
	"strings"

	"github.com/miekg/dns"
)

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

// ErrorHandler responses a given code to client.
type ErrorHandler int

// ServeDNS implements `Handler` interface.
func (e ErrorHandler) ServeDNS(w ResponseWriter, r *Request) {
	w.Msg().Rcode = int(e)
}

var (
	// ErrResponseWritten resulted from writting a written response.
	ErrResponseWritten = errors.New("response has been written")

	// NoErrorHandler responses dns.RcodeSuccess.
	NoErrorHandler = ErrorHandler(dns.RcodeSuccess)

	// NameErrorHandler responses dns.RcodeNameError.
	NameErrorHandler = ErrorHandler(dns.RcodeNameError)

	// FormatErrorHandler responses dns.RcodeFormatError.
	FormatErrorHandler = ErrorHandler(dns.RcodeFormatError)

	// RefusedErrorHandler responses dns.RcodeRefused.
	RefusedErrorHandler = ErrorHandler(dns.RcodeRefused)

	// FailureErrorHandler responses dns.RcodeServerFailure.
	FailureErrorHandler = ErrorHandler(dns.RcodeServerFailure)
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

// CnameHandler restarts query on canonical name.
func CnameHandler(router, h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		if qtype, result := req.Question[0].Qtype, w.Msg(); qtype != dns.TypeCNAME && len(result.Answer) > 0 {
			var cname string
			for _, rr := range result.Answer {
				if rr.Header().Rrtype == dns.TypeCNAME {
					cname = rr.(*dns.CNAME).Target
					break
				}
			}

			if cname != "" {
				cnameWriter := FurtherRequest(w, req, cname, qtype, router)
				result.Rcode = cnameWriter.Rcode
				result.Answer = append(result.Answer, cnameWriter.Answer...)
			}
		}
	})
}

// NsHandler fills out the glue records.
func NsHandler(router, h Handler) Handler {
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
					glueWriter := FurtherRequest(w, req, ns, t, router)
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

// SoaHandler fills out NS records for an original name.
func SoaHandler(router, h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		if result := w.Msg(); len(result.Ns) == 0 && len(result.Answer) > 0 {
			if soa, ok := result.Answer[0].(*dns.SOA); ok {
				result.Authoritative = true
				if soa.Hdr.Name == req.Question[0].Name {
					// adding NS records for an original name
					nsWriter := FurtherRequest(w, req, req.Question[0].Name, dns.TypeNS, router)
					result.Ns = append(result.Ns, nsWriter.Answer...)
					result.Extra = append(result.Extra, nsWriter.Extra...)
				}
			}
		}
	})
}

// ExtraHandler fills out additional A/AAAA records for target names.
func ExtraHandler(router, h Handler, qtype uint16) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		if result := w.Msg(); len(result.Extra) == 0 && len(result.Answer) > 0 {
			for _, rr := range result.Answer {
				if rr.Header().Rrtype != qtype {
					continue
				}

				var target string
				switch qtype {
				case dns.TypeSRV:
					target = rr.(*dns.SRV).Target
				case dns.TypeMX:
					target = rr.(*dns.MX).Mx
				default:
					return
				}

				for _, t := range aTypes {
					extraWriter := FurtherRequest(w, req, target, t, router)
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

// NxHandler fills out a SOA record if occurs NXDOMAIN or NOERROR with no data.
// In addition, NxHandler fills out NS records for non NS queries.
func NxHandler(router, h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, req *Request) {
		h.ServeDNS(w, req)

		result := w.Msg()
		rcode := result.Rcode
		qtype := req.Question[0].Qtype
		qname := req.Question[0].Name
		offset := len(qname)

		if rcode == dns.RcodeNameError {
			offset, _ = dns.NextLabel(qname, 0)
		} else if rcode == dns.RcodeSuccess && qtype != dns.TypeNS && len(result.Answer) == 0 {
			if qtype == dns.TypeSOA {
				offset, _ = dns.NextLabel(qname, 0)
			} else {
				offset = 0
			}
		}

		if offset < len(qname) {
			soaWriter := FurtherRequest(w, req, qname[offset:], dns.TypeSOA, router)
			result.Authoritative = soaWriter.Authoritative
			result.Extra = soaWriter.Extra
			if offset > 0 {
				// NXDOMAIN
				result.Ns = soaWriter.Answer
			} else {
				// NOERROR then NXDOMAIN
				result.Ns = soaWriter.Ns
			}
		}

		if rcode == dns.RcodeSuccess && len(result.Ns) == 0 {
			if qtype != dns.TypeNS {
				offset = 0
			} else if answer := result.Answer; len(answer) == 0 || answer[0].Header().Rrtype != dns.TypeNS {
				offset, _ = dns.NextLabel(qname, 0)
			} else {
				offset = len(qname)
				result.Ns, result.Answer = result.Answer, result.Ns
			}

			if offset < len(qname) {
				nsWriter := FurtherRequest(w, req, qname[offset:], dns.TypeNS, router)
				result.Ns = nsWriter.Ns
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
