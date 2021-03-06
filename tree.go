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
		if c := name[i]; c != ':' && c != '*' {
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
	anonymousCatchAll
)

type wildChildType uint8

const (
	noWildChild wildChildType = iota // default
	namedWildChild
	anonymousWildChild
)

type typeHandler struct {
	Origin      string
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

	originated := true
	if a, ok := h.Handler.(Answer); ok {
		if !strings.HasSuffix(a.Header().Name, h.Origin) {
			originated = false
		}
	}

	switch h.Qtype {
	case dns.TypeNS:
		if originated {
			p.rrType |= rrNs
		}
	case dns.TypeSOA:
		if originated {
			p.rrType |= rrSoa
		}
	case dns.TypeDNAME:
		p.rrType |= rrDname
	}
}

type milestone struct {
	name   string
	node   *node
	params Params
}

type value struct {
	node   *node
	params Params

	// nearest is the nearest node while searching the target name
	nearest milestone
	// cut means search stopped by a dot
	cut bool
	// zones is met zones from up to down while searching name
	zones []milestone
}

// previous returns a previous node by canonical order
func (v value) previous() *node {
	nearestNode := v.nearest.node
	nearestName := v.nearest.name
	nomatch := v.node == nil || v.node.name == "*"

	if nomatch && nearestNode != nil && nearestName != "" {
		c := nearestName[0]
		index := -1

		for i := 0; i < len(nearestNode.indices); i++ {
			if nearestNode.indices[i] == c {
				index = i
				if nearestNode.wildChild == anonymousWildChild {
					// 1st child is reserved for '*'
					index++
				}
				break
			}
		}

		if index != -1 {
			child := nearestNode.children[index]
			if !child.isZone() && child.name < nearestName {
				return child.getMax()
			}
		}

		if c == '.' && nearestNode.data != nil {
			return nearestNode
		}
	} else if v.node.isZone() {
		for i := 0; i < len(v.node.indices); i++ {
			if v.node.indices[i] != '.' {
				continue
			}

			j := i
			if v.node.wildChild != noWildChild {
				j++
			}
			child := v.node.children[j].getMax()
			if child.data != nil {
				return child
			}
			break
		}

		return v.node
	}

	var zone *node
	if v.zones != nil {
		zone = v.zones[len(v.zones)-1].node
	}

up:
	if nearestNode != nil && nearestName != "" {
		c := nearestName[0]

		var chars [255]uint16
		if nearestNode.wildChild == anonymousWildChild && c > '*' {
			chars['*'] = 1
		}

		dot := -1
		for i := 0; i < len(nearestNode.indices); i++ {
			ch := nearestNode.indices[i]
			if ch == '.' {
				dot = i
			} else if ch < c {
				j := i + 1
				if nearestNode.wildChild != noWildChild {
					// 1st child is reserved for '*'
					j++
				}
				chars[ch] = uint16(j)
			}
		}

		// first try indices
		for i := len(chars) - 1; i >= 0; i-- {
			if j := chars[i]; j > 0 {
				child := nearestNode.children[j-1]
				if child.isZone() {
					grandchild := child.getMaxChild()
					if grandchild != nil {
						return grandchild
					}
					if nomatch {
						return child
					}
					continue
				}
				return child.getMax()
			}
		}

		// then try dot
		if dot != -1 {
			if c == '.' && nearestNode.isZone() {
				return nearestNode
			}

			if c != '.' && !nearestNode.isZone() {
				i := dot
				if nearestNode.wildChild != noWildChild {
					i++
				}
				return nearestNode.children[i].getMax()
			}
		}

		// next try present
		if nearestNode.data != nil && !nearestNode.isZone() {
			return nearestNode
		}

		// finally go up
		for nearestNode.parent != nil {
			if nearestNode.parent == zone {
				return zone
			}

			nearestName = nearestNode.name
			nearestNode = nearestNode.parent

			if nearestName != "" {
				goto up
			}
		}
	}

	return v.nearest.node.getMax()
}

// revertParams reverts params according to indexable domain
func (v *value) revertParams() {
	for i, param := range v.params {
		if dns.CountLabel(param.Value) > 1 {
			v.params[i].Value = indexable(param.Value)
		}
	}
	for i, j := 0, len(v.params)-1; i < j; i, j = i+1, j-1 {
		v.params[i], v.params[j] = v.params[j], v.params[i]
	}

	for i, zone := range v.zones {
		if len(zone.params) < len(v.params) {
			v.zones[i].params = v.params[len(v.params)-len(zone.params):]
		} else {
			break
		}
	}
}

type node struct {
	name      string
	wildChild wildChildType
	nType     nodeType
	maxParams uint8
	indices   string
	children  []*node
	parent    *node
	data      *nodeData
	priority  uint32
}

// increments priority of the given child and reorders if necessary
func (n *node) incrementChildPrio(pos int) int {
	children := n.children
	if n.wildChild != noWildChild {
		// since indices doesn't contain wildcard, so has to step forward 1 child
		children = children[1:]
	}
	children[pos].priority++
	prio := children[pos].priority

	// adjust position (move to front)
	newPos := pos
	for newPos > 0 && n.children[newPos-1].priority < prio {
		// swap node positions
		children[newPos-1], children[newPos] = children[newPos], children[newPos-1]

		newPos--
	}

	// build new index char string
	if newPos != pos {
		n.indices = n.indices[:newPos] + // unchanged prefix, might be empty
			n.indices[pos:pos+1] + // the index char we move
			n.indices[newPos:pos] + n.indices[pos+1:] // rest without char at 'pos'
	}

	if n.wildChild != noWildChild {
		// since index 0 is reserved for wildChild, so makes a increase
		newPos++
	}
	return newPos
}

// addRoute adds a node with the given handler to the name.
// Not concurrency-safe!
func (n *node) addRoute(name string, allowDup bool, handler typeHandler) {
	//var anonymousParent *node
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
				child := &node{
					name:      n.name[i:],
					wildChild: n.wildChild,
					nType:     static,
					indices:   n.indices,
					children:  n.children,
					parent:    n,
					data:      n.data,
					priority:  n.priority - 1,
				}

				// Update maxParams (max of all children)
				for i := range child.children {
					if child.children[i].maxParams > child.maxParams {
						child.maxParams = child.children[i].maxParams
					}
					child.children[i].parent = child
				}

				n.children = []*node{child}
				// []byte for proper unicode char conversion, see #65
				n.indices = string([]byte{n.name[i]})
				n.name = name[:i]
				n.data = nil
				n.wildChild = noWildChild
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
						n = n.children[i]
						continue walk
					}
				}

				// Otherwise insert it
				if c != ':' && c != '*' {
					// []byte for proper unicode char conversion, see #65
					n.indices += string([]byte{c})
					child := &node{
						maxParams: numParams,
						parent:    n,
					}
					n.children = append(n.children, child)
					n.incrementChildPrio(len(n.indices) - 1)
					n = child
				}
				if n.wildChild == anonymousWildChild {
					if !allowDup {
						panic("a handle is already registered for name '" + fullName + "'")
					}

					child := n.children[0]
					child.data.addHandler(handler)
					child.priority++
				} else {
					n.insertChild(numParams, name, fullName, handler)
				}
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

		// anonymous wildcard
		if c == '*' && end == max && strings.HasSuffix(fullName, ".*") {
			// split name at the beginning of the wildcard
			if i > 0 {
				n.name = name[offset:i]
				offset = i
			}

			child := &node{
				nType:     anonymousCatchAll,
				maxParams: numParams,
				priority:  1,
				parent:    n,
			}
			n.children = append([]*node{child}, n.children...)
			n.wildChild = anonymousWildChild
			n = child
			break
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
				parent:    n,
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
					parent:    n,
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
				parent:    n,
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
				parent:    n,
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

// Returns the handler registered with the given name (key).
func (n *node) getValue(name string) (v value) {
	var (
		end int
		p   Params

		// TODO: Is there an real case that an asterisk across multiple zones?

		// fallback variables are relative to anonymous wildcards.
		fallback       bool
		fallbackNode   *node
		fallbackName   string
		fallbackParams Params
	)

	defer func() {
		v.params = p

		if v.node != nil && v.node.data.rrType&rrZone > 0 {
			if v.zones == nil {
				v.zones = make([]milestone, 0, dns.CountLabel(name)+1)
			}
			i := len(v.zones)
			v.zones = v.zones[:i+1] // expand slice within preallocated capacity
			v.zones[i].node = n
			v.zones[i].params = p
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

	v.nearest.node = n
	v.nearest.name = name

walk: // outer loop for walking the tree
	for {
		if len(name) > len(n.name) && name[:len(n.name)] == n.name {
			if n.wildChild == anonymousWildChild {
				fallbackNode, fallbackName, fallbackParams = n, name, p
			}

			name = name[len(n.name):]

			if !fallback {
				v.nearest.node, v.nearest.params, v.nearest.name = n, p, name
			}

			if n.data != nil && strings.HasPrefix(name, ".") {
				if n.data.rrType&rrZone > 0 {
					if v.zones == nil {
						v.zones = make([]milestone, 0, dns.CountLabel(name)+1)
					}
					i := len(v.zones)
					v.zones = v.zones[:i+1] // expand slice within preallocated capacity
					v.zones[i].node = n
					v.zones[i].params = p
					v.zones[i].name = name
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
			if n.wildChild != namedWildChild && !fallback {
				c := name[0]

				for i := 0; i < len(n.indices); i++ {
					if c == n.indices[i] {
						if n.wildChild != noWildChild {
							// since indices doesn't contain wildcard, so use the next child
							n = n.children[i+1]
						} else {
							n = n.children[i]
						}
						continue walk
					}
				}

				// Nothing found.
				if fallbackNode != nil && !fallback {
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
					// lazy allocation
					p = make(Params, 0, n.maxParams)
				}
				i := len(p)
				p = p[:i+1] // expand slice within preallocated capacity
				p[i].Key = n.name[1:]
				p[i].Value = name[:end]

				// we need to go deeper! end is stopped by dot
				if end < len(name) {
					if n.data != nil {
						if n.data.rrType&rrZone > 0 {
							if v.zones == nil {
								v.zones = make([]milestone, 0, dns.CountLabel(name)+1)
							}
							i := len(v.zones)
							v.zones = v.zones[:i+1] // expand slice within preallocated capacity
							v.zones[i].node = n
							v.zones[i].params = p
							v.zones[i].name = name
						}

						if n.data.rrType&rrDname > 0 {
							v.node = n
							return
						}
					}

					if len(n.children) > 0 {
						name = name[end:]
						v.nearest.node, v.nearest.params, v.nearest.name = n, p, name
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

			case anonymousCatchAll:
				// save param value
				if p == nil {
					// lazy allocation
					p = make(Params, 0, n.maxParams+1)
				}
				i := len(p)
				p = p[:i+1] // expand slice within preallocated capacity
				p[i].Value = name

				if n.data != nil {
					v.node = n
				}
				return

			default:
				panic("invalid node type")
			}
		} else if name == n.name {
			// We should have reached the node containing the handle.
			if n.data != nil {
				v.node = n
			}
		} else {
			if fallback {
				if n.name == "*" {
					// save param value
					if p == nil {
						// lazy allocation
						p = make(Params, 0, n.maxParams)
					}
					i := len(p)
					p = p[:i+1] // expand slice within preallocated capacity
					p[i].Value = name

					if n.data != nil {
						v.node = n
					}

					return
				}

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

// returns the maximum node
func (n *node) getMax() *node {
	if n != nil && len(n.children) > 0 {
		if len(n.indices) == 0 {
			child := n.children[0]
			if child.isZone() {
				grandchild := child.getMaxChild()
				if grandchild != nil {
					return grandchild
				}
				return n
			}

			if v := child.getMax(); v.data != nil {
				return v
			}
			return n
		}

		var chars [255]uint16
		for i := 0; i < len(n.indices); i++ {
			j := i + 1
			if n.wildChild != noWildChild {
				j++
			}
			chars[n.indices[i]] = uint16(j)
		}

		for i := len(chars) - 1; i >= 0; i-- {
			if j := chars[i]; j > 0 {
				child := n.children[j-1]
				if child.isZone() {
					grandchild := child.getMaxChild()
					if grandchild != nil {
						return grandchild
					}
					continue
				}

				if v := child.getMax(); v.data != nil {
					return v
				}
				return n
			}
		}
	}

	return n
}

func (n *node) getMaxChild() *node {
	nop := true

	var chars [255]uint16
	for i := 0; i < len(n.indices); i++ {
		if n.indices[i] == '.' {
			continue
		}

		nop = false
		j := i + 1
		if n.wildChild != noWildChild {
			j++
		}
		chars[n.indices[i]] = uint16(j)
	}

	if !nop {
		for i := len(chars) - 1; i >= 0; i-- {
			if j := chars[i]; j > 0 {
				child := n.children[j-1]
				if child.isZone() {
					grandchild := child.getMaxChild()
					if grandchild != nil {
						return grandchild
					}
					continue
				}

				if v := child.getMax(); v.data != nil {
					return v
				}
				return n
			}
		}
	}
	return nil
}

func (n *node) isZone() bool {
	return n != nil && n.data != nil && n.data.rrType&rrZone > 0
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
