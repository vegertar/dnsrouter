// Copyright 2013 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// at https://github.com/julienschmidt/httprouter/blob/master/LICENSE

package dnsrouter

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}

func countParams(name string) uint8 {
	var n uint
	for i := 0; i < len(name); i++ {
		if name[i] != ':' && name[i] != '*' {
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

type nodeHandlerElement struct {
	Qtype       uint16
	TypeCovered uint16
	Handler     Handler
}

// NodeHandler is the data associating with a node in tree.
type NodeHandler []nodeHandlerElement

func (l NodeHandler) Len() int {
	return len(l)
}

func (l NodeHandler) Less(a, b int) bool {
	return l[a].Qtype < l[b].Qtype ||
		l[a].Qtype == l[b].Qtype && l[a].TypeCovered < l[b].TypeCovered
}

func (l NodeHandler) Swap(a, b int) {
	l[a], l[b] = l[b], l[a]
}

// Search returns a slice matching with qtype.
func (l NodeHandler) Search(qtype uint16) NodeHandler {
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
func (l NodeHandler) SearchCovered(typeCovered uint16) NodeHandler {
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
func (l NodeHandler) ServeDNS(w ResponseWriter, r *Request) {
	for _, h := range l {
		if h.Handler != nil {
			h.Handler.ServeDNS(w, r)
		}
	}
}

type node struct {
	name      string
	wildChild bool
	nType     nodeType
	maxParams uint8
	indices   string
	children  []*node
	handler   NodeHandler
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
func (n *node) addRoute(name string, allowDup bool, handler nodeHandlerElement) {
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
					handler:   n.handler,
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
				n.handler = nil
				n.wildChild = false
			}

			// Make new node a child of this node
			if i < len(name) {
				name = name[i:]

				if n.wildChild {
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
					}
					n.children = append(n.children, child)
					n.incrementChildPrio(len(n.indices) - 1)
					n = child
				}
				n.insertChild(numParams, name, fullName, handler)
				return

			} else if i == len(name) { // Make node a (in-name) leaf
				if len(n.handler) != 0 && !allowDup {
					panic("a handle is already registered for name '" + fullName + "'")
				}
				n.handler = append(n.handler, handler)
				sort.Sort(n.handler)
			}
			return
		}
	} else { // Empty tree
		n.insertChild(numParams, name, fullName, handler)
		n.nType = root
	}
}

func (n *node) insertChild(numParams uint8, name, fullName string, handler nodeHandlerElement) {
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
			n.wildChild = true
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
				wildChild: true,
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
				handler:   []nodeHandlerElement{handler},
				priority:  1,
			}
			n.children = []*node{child}

			return
		}
	}

	// insert remaining name part and handler to the leaf
	n.name = name[offset:]
	n.handler = []nodeHandlerElement{handler}
}

// Returns the handler registered with the given name (key). The values of
// wildcards are saved to a map. The third returned value cut indicating whether
// the searching is ending at a cut of a name.
func (n *node) getValue(name string) (handler NodeHandler, p Params, cut bool) {
	var end int

	defer func() {
		if l := len(name); handler == nil {
			switch n.nType {
			case static:
				cut = l < len(n.name) && n.name[l] == '.'
			case param:
				// both name and n.name have no child.
				cut = end == len(name)
			}
		}
	}()
walk: // outer loop for walking the tree
	for {
		if len(name) > len(n.name) && name[:len(n.name)] == n.name {
			name = name[len(n.name):]
			// If this node does not have a wildcard (param or catchAll)
			// child,  we can just look up the next child node and continue
			// to walk down the tree
			if !n.wildChild {
				c := name[0]
				for i := 0; i < len(n.indices); i++ {
					if c == n.indices[i] {
						n = n.children[i]
						continue walk
					}
				}

				// Nothing found.
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

				// we need to go deeper!
				if end < len(name) {
					if len(n.children) > 0 {
						name = name[end:]
						n = n.children[0]
						continue walk
					}

					// ... but we can't
					return
				}

				if len(n.handler) > 0 {
					handler = n.handler
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

				if len(n.handler) > 0 {
					handler = n.handler
				}
				return

			default:
				panic("invalid node type")
			}
		} else if name == n.name && len(n.handler) > 0 {
			// We should have reached the node containing the handle.
			handler = n.handler
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
			if !n.wildChild {
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

				return ciName, n.handler != nil

			case catchAll:
				return append(ciName, name...), true

			default:
				panic("invalid node type")
			}
		} else {
			return ciName, n.handler != nil
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
