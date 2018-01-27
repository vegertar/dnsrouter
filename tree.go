// Copyright 2013 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// at https://github.com/julienschmidt/httprouter/blob/master/LICENSE

package dnsrouter

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/miekg/dns"
)

type paramContextKeyType int

const paramContextKey paramContextKeyType = 0

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

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}

func countParams(name string) uint8 {
	var n uint
	for i := 0; i < len(name); i++ {
		if c := name[i]; c != ':' && c != '*' || c == '*' && i+1 == len(name) {
			continue
		}
		n++
	}
	if n >= 255 {
		return 255
	}
	return uint8(n)
}

type nodeType uint8

const (
	static nodeType = iota // default
	root
	param
	catchAll
)

type wildChildType uint8

const (
	noWildChild wildChildType = iota // default
	namedWildChild
	anonymousWildChild
)

type typeHandler struct {
	Qtype       uint16
	TypeCovered uint16
	Handler     Handler
}

type classHandler []typeHandler

func (l classHandler) Len() int {
	return len(l)
}

func (l classHandler) Less(a, b int) bool {
	return l[a].Qtype < l[b].Qtype ||
		l[a].Qtype == l[b].Qtype && l[a].TypeCovered < l[b].TypeCovered
}

func (l classHandler) Swap(a, b int) {
	l[a], l[b] = l[b], l[a]
}

// Search returns a slice matching with qtype.
func (l classHandler) Search(qtype uint16) classHandler {
	i := sort.Search(len(l), func(i int) bool {
		return l[i].Qtype >= qtype
	})

	offset := -1
	for i < len(l) && l[i].Qtype == qtype {
		if offset == -1 {
			offset = i
		}
		i++
	}
	if offset != -1 {
		return l[offset:i]
	}
	return nil
}

// SearchCovered returns a slice matching with typeCovered.
// This method should be called on a slice returned from method .Search(qtype).
func (l classHandler) SearchCovered(typeCovered uint16) classHandler {
	i := sort.Search(len(l), func(i int) bool {
		return l[i].TypeCovered >= typeCovered
	})

	offset := -1
	for i < len(l) && l[i].TypeCovered == typeCovered {
		if offset == -1 {
			offset = i
		}
		i++
	}
	if offset != -1 {
		return l[offset:i]
	}
	return nil
}

// ServeDNS implements Handler interface.
func (l classHandler) ServeDNS(w ResponseWriter, r *Request) {
	for _, h := range l {
		if h.Handler != nil {
			h.Handler.ServeDNS(w, r)
		}
	}
}

type rrType uint8

const (
	rrNs    rrType = 1 << iota
	rrSoa          = 1 << iota
	rrDname        = 1 << iota

	rrZone = rrNs | rrSoa
)

type nodeData struct {
	handler classHandler
	rrType  rrType
}

func (p *nodeData) addHandler(h typeHandler) {
	p.handler = append(p.handler, h)
	if len(p.handler) > 1 {
		sort.Sort(p.handler)
	}
	switch h.Qtype {
	case dns.TypeNS:
		p.rrType |= rrNs
	case dns.TypeSOA:
		p.rrType |= rrSoa
	case dns.TypeDNAME:
		p.rrType |= rrDname
	}
}

type value struct {
	node   *node
	params Params
	cut    bool // cut means search stopped by a dot
	zone   struct {
		node   *node
		params Params
	}
}

// TODO: this is a NSEC-specific lookup.
func (v value) getPrevNode() *node {
	if v.zone.node == nil {
		return nil
	}

	return nil
}

// this is used to revert params according to indexable domain
func (v *value) revertParams() {
	for i, param := range v.params {
		if dns.CountLabel(param.Value) > 1 {
			v.params[i].Value = indexable(param.Value)
		}
	}
	for i, j := 0, len(v.params)-1; i < j; i, j = i+1, j-1 {
		v.params[i], v.params[j] = v.params[j], v.params[i]
	}

	if len(v.zone.params) < len(v.params) {
		v.zone.params = v.params[len(v.params)-len(v.zone.params):]
	}
}

type node struct {
	name      string
	wildChild wildChildType
	nType     nodeType
	maxParams uint8
	indices   string
	children  []*node
	data      *nodeData
	priority  uint32
}

// increments priority of the given child and reorders if necessary
func (n *node) incrementChildPrio(pos int) int {
	n.children[pos].priority++
	prio := n.children[pos].priority

	// adjust position (move to front)
	newPos := pos
	for newPos > 0 && n.children[newPos-1].priority < prio {
		// swap node positions
		n.children[newPos-1], n.children[newPos] = n.children[newPos], n.children[newPos-1]

		newPos--
	}

	// build new index char string
	if newPos != pos {
		n.indices = n.indices[:newPos] + // unchanged prefix, might be empty
			n.indices[pos:pos+1] + // the index char we move
			n.indices[newPos:pos] + n.indices[pos+1:] // rest without char at 'pos'
	}

	return newPos
}

// addRoute adds a node with the given handler to the name.
// Not concurrency-safe!
func (n *node) addRoute(name string, allowDup bool, handler typeHandler) {
	var anonymousParent *node
	fullName := name
	n.priority++
	numParams := countParams(name)

	// non-empty tree
	if len(n.name) > 0 || len(n.children) > 0 {
	walk:
		for {
			// Update maxParams of the current node
			if numParams > n.maxParams {
				n.maxParams = numParams
			}

			// Find the longest common prefix.
			// This also implies that the common prefix contains no ':' or '*'
			// since the existing key can't contain those chars.
			i := 0
			max := min(len(name), len(n.name))
			for i < max && name[i] == n.name[i] {
				i++
			}

			// Split edge
			if i < len(n.name) {
				child := node{
					name:      n.name[i:],
					wildChild: n.wildChild,
					nType:     static,
					indices:   n.indices,
					children:  n.children,
					data:      n.data,
					priority:  n.priority - 1,
				}

				// Update maxParams (max of all children)
				for i := range child.children {
					if child.children[i].maxParams > child.maxParams {
						child.maxParams = child.children[i].maxParams
					}
				}

				n.children = []*node{&child}
				// []byte for proper unicode char conversion, see #65
				n.indices = string([]byte{n.name[i]})
				n.name = name[:i]
				n.data = nil
				n.wildChild = noWildChild
				if anonymousParent != nil {
					anonymousParent.wildChild = noWildChild
					n.wildChild = anonymousWildChild
					anonymousParent = nil
				}
			}

			// Make new node a child of this node
			if i < len(name) {
				name = name[i:]

				if n.wildChild == namedWildChild {
					n = n.children[0]
					n.priority++

					// Update maxParams of the child node
					if numParams > n.maxParams {
						n.maxParams = numParams
					}
					numParams--

					// Check if the wildcard matches
					if len(name) >= len(n.name) && n.name == name[:len(n.name)] &&
						// Check for longer wildcard, e.g. :name and :names
						(len(n.name) >= len(name) || name[len(n.name)] == '.') {
						continue walk
					} else {
						// Wildcard conflict
						var nameSeg string
						if n.nType == catchAll {
							nameSeg = name
						} else {
							nameSeg = strings.SplitN(name, ".", 2)[0]
						}
						prefix := fullName[:strings.Index(fullName, nameSeg)] + n.name
						panic("'" + nameSeg +
							"' in new name '" + fullName +
							"' conflicts with existing wildcard '" + n.name +
							"' in existing prefix '" + prefix +
							"'")
					}
				}

				c := name[0]

				// dot after param
				if n.nType == param && c == '.' && len(n.children) == 1 {
					n = n.children[0]
					n.priority++
					continue walk
				}

				// Check if a child with the next name byte exists
				for i := 0; i < len(n.indices); i++ {
					if c == n.indices[i] {
						i = n.incrementChildPrio(i)
						if n.wildChild == anonymousWildChild {
							anonymousParent = n
						} else {
							anonymousParent = nil
						}
						n = n.children[i]
						continue walk
					}
				}

				// Otherwise insert it
				if c != ':' && c != '*' || strings.HasSuffix(name, "*") {
					// []byte for proper unicode char conversion, see #65
					n.indices += string([]byte{c})
					if strings.HasSuffix(name, "*") {
						n.wildChild = anonymousWildChild
					}
					child := &node{
						maxParams: numParams,
					}
					n.children = append(n.children, child)
					n.incrementChildPrio(len(n.indices) - 1)
					n = child
				}
				n.insertChild(numParams, name, fullName, handler)
				return

			} else if i == len(name) { // Make node a (in-name) leaf
				if n.data != nil && !allowDup {
					panic("a handle is already registered for name '" + fullName + "'")
				}
				if n.data == nil {
					n.data = new(nodeData)
				}
				n.data.addHandler(handler)
			}
			return
		}
	} else { // Empty tree
		n.insertChild(numParams, name, fullName, handler)
		n.nType = root
	}
}

func (n *node) insertChild(numParams uint8, name, fullName string, handler typeHandler) {
	var offset int // already handled bytes of the name

	// find prefix until first wildcard (beginning with ':'' or '*'')
	for i, max := 0, len(name); numParams > 0; i++ {
		c := name[i]
		if c != ':' && c != '*' {
			continue
		}

		// find wildcard end (either '.' or name end)
		end := i + 1
		for end < max && name[end] != '.' {
			switch name[end] {
			// the wildcard name must not contain ':' and '*'
			case ':', '*':
				panic("only one wildcard per name segment is allowed, has: '" +
					name[i:] + "' in name '" + fullName + "'")
			default:
				end++
			}
		}

		// check if this Node existing children which would be
		// unreachable if we insert the wildcard here
		if len(n.children) > 0 {
			panic("wildcard route '" + name[i:end] +
				"' conflicts with existing children in name '" + fullName + "'")
		}

		// check if the wildcard has a name
		if end-i < 2 {
			panic("wildcards must be named with a non-empty name in name '" + fullName + "'")
		}

		if c == ':' { // param
			// split name at the beginning of the wildcard
			if i > 0 {
				n.name = name[offset:i]
				offset = i
			}

			child := &node{
				nType:     param,
				maxParams: numParams,
			}
			n.children = []*node{child}
			n.wildChild = namedWildChild
			n = child
			n.priority++
			numParams--

			// if the name doesn't end with the wildcard, then there
			// will be another non-wildcard subname starting with '.'
			if end < max {
				n.name = name[offset:end]
				offset = end

				child := &node{
					maxParams: numParams,
					priority:  1,
				}
				n.children = []*node{child}
				n = child
			}

		} else { // catchAll
			if end != max || numParams > 1 {
				panic("catch-all routes are only allowed at the end of the name in name '" + fullName + "'")
			}

			if len(n.name) > 0 && n.name[len(n.name)-1] == '.' {
				panic("catch-all conflicts with existing handler for the name segment root in name '" + fullName + "'")
			}

			// currently fixed width 1 for '.'
			i--
			if name[i] != '.' {
				panic("no . before catch-all in name '" + fullName + "'")
			}

			n.name = name[offset:i]

			// first node: catchAll node with empty name
			child := &node{
				wildChild: namedWildChild,
				nType:     catchAll,
				maxParams: 1,
			}
			n.children = []*node{child}
			n.indices = string(name[i])
			n = child
			n.priority++

			// second node: node holding the variable
			child = &node{
				name:      name[i:],
				nType:     catchAll,
				maxParams: 1,
				data:      new(nodeData),
				priority:  1,
			}
			child.data.addHandler(handler)
			n.children = []*node{child}

			return
		}
	}

	// insert remaining name part and handler to the leaf
	n.name = name[offset:]
	if n.data == nil {
		n.data = new(nodeData)
	}
	n.data.addHandler(handler)
}

// Returns the handler registered with the given name (key). The values of
// wildcards are saved to a map. The third returned value cut indicating whether
// the searching is ending at a cut of a name.
func (n *node) getValue(name string) (v value) {
	var (
		end            int
		fallbackNode   *node
		fallbackName   string
		fallbackParams Params
		fallback       bool
		p              Params
	)

	defer func() {
		v.params = p

		if v.node != nil && v.node.data.rrType&rrZone > 0 {
			v.zone.node, v.zone.params = n, p
		}

		if v.node == nil {
			switch n.nType {
			case static, root:
				l := len(name)
				v.cut = l < len(n.name) && n.name[l] == '.' && n.name[:l] == name
			case param:
				// both name and n.name have no child.
				v.cut = end == len(name)
			}
		}
	}()

walk: // outer loop for walking the tree
	for {
		if len(name) > len(n.name) && name[:len(n.name)] == n.name {
			if n.wildChild == anonymousWildChild {
				fallbackNode, fallbackName, fallbackParams = n, name, p
			}

			name = name[len(n.name):]

			if n.data != nil && strings.HasPrefix(name, ".") {
				if n.data.rrType&rrZone > 0 {
					v.zone.node, v.zone.params = n, p
				}

				if n.data.rrType&rrDname > 0 {
					v.node = n
					v.cut = true
					return
				}
			}

			// If this node does not have a wildcard (param or catchAll)
			// child,  we can just look up the next child node and continue
			// to walk down the tree
			if n.wildChild != 1 {
				c := name[0]
				if fallback {
					c = '*'
				}

				for i := 0; i < len(n.indices); i++ {
					if c == n.indices[i] {
						n = n.children[i]
						continue walk
					}
				}

				// Nothing found.
				if fallbackNode != nil {
					n, name, p, fallback = fallbackNode, fallbackName, fallbackParams, true
					continue walk
				}
				return
			}

			// handle wildcard child
			n = n.children[0]
			switch n.nType {
			case param:
				// find param end (either '.' or name end)
				end = 0
				for end < len(name) && name[end] != '.' {
					end++
				}

				// save param value
				if p == nil {
					// lazy allocation, the additional 1 space is reserved for anonymous wildcard
					p = make(Params, 0, n.maxParams+1)
				}
				i := len(p)
				p = p[:i+1] // expand slice within preallocated capacity
				p[i].Key = n.name[1:]
				p[i].Value = name[:end]

				// we need to go deeper!
				if end < len(name) {
					if n.data != nil {
						if n.data.rrType&rrZone > 0 {
							v.zone.node, v.zone.params = n, p
						}

						if n.data.rrType&rrDname > 0 {
							v.node = n
							return
						}
					}

					if len(n.children) > 0 {
						name = name[end:]
						n = n.children[0]
						continue walk
					}

					// ... but we can't
					if fallbackNode != nil {
						n, name, p, fallback = fallbackNode, fallbackName, fallbackParams, true
						continue walk
					}
					return
				}

				if n.data != nil {
					v.node = n
				}

				return

			case catchAll:
				// save param value
				if p == nil {
					// lazy allocation
					p = make(Params, 0, n.maxParams)
				}
				i := len(p)
				p = p[:i+1] // expand slice within preallocated capacity
				p[i].Key = n.name[2:]
				p[i].Value = name

				if n.data != nil {
					v.node = n
				}
				return

			default:
				panic("invalid node type")
			}
		} else if name == n.name && n.data != nil {
			// We should have reached the node containing the handle.
			v.node = n
		} else {
			if fallback && n.name == "*" || strings.HasSuffix(n.name, ".*") {
				if dot := strings.LastIndex(n.name, ".*"); dot != -1 {
					if len(name) <= dot || name[:dot+1] != n.name[:dot+1] {
						return
					}
					name = name[dot+1:]
				}

				if n.data != nil {
					v.node = n
				}

				// save param value
				if p == nil {
					// lazy allocation
					p = make(Params, 0, n.maxParams+1)
				}
				i := len(p)
				p = p[:i+1] // expand slice within preallocated capacity
				p[i].Value = name
				return
			}

			if fallback {
				panic("failed fallback for route: " + n.name + " and name: " + name)
			}

			if fallbackNode != nil {
				n, name, p, fallback = fallbackNode, fallbackName, fallbackParams, true
				continue walk
			}
		}

		return
	}
}

// Makes a case-insensitive lookup of the given name and tries to find a handler.
// It returns the case-corrected name indicating whether the lookup was successful.
func (n *node) findCaseInsensitiveName(name string) (ciName []byte, found bool) {
	return n.findCaseInsensitiveNameRec(
		name,
		strings.ToLower(name),
		make([]byte, 0, len(name)+1), // preallocate enough memory for new name
		[4]byte{},                    // empty rune buffer
	)
}

// recursive case-insensitive lookup function used by n.findCaseInsensitiveName
func (n *node) findCaseInsensitiveNameRec(name, loName string, ciName []byte, rb [4]byte) ([]byte, bool) {
	loNName := strings.ToLower(n.name)

walk: // outer loop for walking the tree
	for len(loName) >= len(loNName) && (len(loNName) == 0 || loName[1:len(loNName)] == loNName[1:]) {
		// add common name to result
		ciName = append(ciName, n.name...)

		if name = name[len(n.name):]; len(name) > 0 {
			loOld := loName
			loName = loName[len(loNName):]

			// If this node does not have a wildcard (param or catchAll) child,
			// we can just look up the next child node and continue to walk down
			// the tree
			if n.wildChild == noWildChild {
				// skip rune bytes already processed
				rb = shiftNRuneBytes(rb, len(loNName))

				if rb[0] != 0 {
					// old rune not finished
					for i := 0; i < len(n.indices); i++ {
						if n.indices[i] == rb[0] {
							// continue with child node
							n = n.children[i]
							loNName = strings.ToLower(n.name)
							continue walk
						}
					}
				} else {
					// process a new rune
					var rv rune

					// find rune start
					// runes are up to 4 byte long,
					// -4 would definitely be another rune
					var off int
					for max := min(len(loNName), 3); off < max; off++ {
						if i := len(loNName) - off; utf8.RuneStart(loOld[i]) {
							// read rune from cached lowercase name
							rv, _ = utf8.DecodeRuneInString(loOld[i:])
							break
						}
					}

					// calculate lowercase bytes of current rune
					utf8.EncodeRune(rb[:], rv)
					// skipp already processed bytes
					rb = shiftNRuneBytes(rb, off)

					for i := 0; i < len(n.indices); i++ {
						// lowercase matches
						if n.indices[i] == rb[0] {
							// must use a recursive approach since both the
							// uppercase byte and the lowercase byte might exist
							// as an index
							if out, found := n.children[i].findCaseInsensitiveNameRec(
								name, loName, ciName, rb,
							); found {
								return out, true
							}
							break
						}
					}

					// same for uppercase rune, if it differs
					if up := unicode.ToUpper(rv); up != rv {
						utf8.EncodeRune(rb[:], up)
						rb = shiftNRuneBytes(rb, off)

						for i := 0; i < len(n.indices); i++ {
							// uppercase matches
							if n.indices[i] == rb[0] {
								// continue with child node
								n = n.children[i]
								loNName = strings.ToLower(n.name)
								continue walk
							}
						}
					}
				}

				// Nothing found.
				return ciName, false
			}

			n = n.children[0]
			switch n.nType {
			case param:
				// find param end (either '.' or name end)
				k := 0
				for k < len(name) && name[k] != '.' {
					k++
				}

				// add param value to case insensitive name
				ciName = append(ciName, name[:k]...)

				// we need to go deeper!
				if k < len(name) {
					if len(n.children) > 0 {
						// continue with child node
						n = n.children[0]
						loNName = strings.ToLower(n.name)
						loName = loName[k:]
						name = name[k:]
						continue
					}

					// ... but we can't
					return ciName, false
				}

				return ciName, n.data != nil

			case catchAll:
				return append(ciName, name...), true

			default:
				panic("invalid node type")
			}
		} else {
			return ciName, n.data != nil
		}
	}

	// Nothing found.
	return ciName, false
}

// shift bytes in array by n bytes left
func shiftNRuneBytes(rb [4]byte, n int) [4]byte {
	switch n {
	case 0:
		return rb
	case 1:
		return [4]byte{rb[1], rb[2], rb[3], 0}
	case 2:
		return [4]byte{rb[2], rb[3]}
	case 3:
		return [4]byte{rb[3]}
	default:
		return [4]byte{}
	}
}
