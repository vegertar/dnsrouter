package dnsrouter

import (
	"sort"
	"strconv"
	"strings"
)

const wildcardKey = "\200"

type wildcardNode struct {
	name    string
	handler NodeHandler
}

type wildcardTree []wildcardNode

func (w wildcardTree) Len() int {
	return len(w)
}

func (w wildcardTree) Less(a, b int) bool {
	return canonicalOrderLess(w[a].name, w[b].name)
}

func (w wildcardTree) Swap(a, b int) {
	w[a], w[b] = w[b], w[a]
}

func (w wildcardTree) search(name string) int {
	i := sort.Search(len(w), func(i int) bool {
		return !canonicalOrderLess(w[i].name, name)
	})
	return i
}

func (w *wildcardTree) addRoute(name string, allowDup bool, handler nodeHandlerElement) {
	noWildcard := true

	// appending an anonymous name
	if strings.HasSuffix(name, ".*") {
		name += wildcardKey
		noWildcard = false
	}
	for i := 0; i < len(name); i++ {
		nextDot := strings.Index(name[i:], ".")
		if name[i] == '*' && nextDot != -1 {
			panic(name + ": wildcard '*' has to be the last label")
		}
		if name[i] == ':' || name[i] == '*' {
			if i+1 == len(name) || name[i+1] == '.' {
				panic(name + ": missing parameter name on index " + strconv.Itoa(i))
			}
			if name[i] == '*' && (i == 0 || name[i-1] != '.') {
				panic(name + ": wildcard '*' must appear behind the '.'")
			}
			if nextDot != -1 {
				i += nextDot
			}
		}
		if name[i] == '*' {
			noWildcard = false
		}
	}
	if noWildcard {
		panic(name + ": only wildcard names are permitted")
	}

	if i := w.search(name); i < w.Len() && (*w)[i].name == name {
		if !allowDup {
			panic(name + ": existed route")
		}
		(*w)[i].handler = append((*w)[i].handler, handler)
		sort.Sort((*w)[i].handler)
	} else {
		*w = append(*w, wildcardNode{name: name, handler: NodeHandler{handler}})
		sort.Sort(*w)
	}
}

func (w *wildcardTree) getValue(name string) (handler NodeHandler, p Params, cut bool) {
	var (
		matched   bool
		params    [255]Param
		paramSize int
	)

	index := w.search(name)
	for i, n := index, w.Len(); i < n && !matched; i++ {
		paramSize = 0
		route := (*w)[i].name

		for j, k := 0, 0; j < len(route) && k < len(name) && !matched; j, k = j+1, k+1 {
			var param Param
			if c := route[j]; c == ':' {
				nextRouteDot := strings.Index(route[j:], ".")
				if nextRouteDot != -1 {
					param.Key = route[j+1 : j+nextRouteDot]
					j += nextRouteDot
				} else {
					param.Key = route[j+1:]
					j += len(route)
				}

				nextNameDot := strings.Index(name[k:], ".")
				if nextNameDot != -1 {
					param.Value = name[k : k+nextNameDot]
					k += nextNameDot
				} else {
					param.Value = name[k:]
					k += len(name)
				}

				if nextRouteDot == -1 && nextNameDot == -1 ||
					j+1 == len(route) && k+1 == len(name) {
					matched = true
				}
			} else if c == '*' {
				matched = true
				param.Key = route[j+1:]
				param.Value = name[k:]
			} else if c != name[k] {
				break
			} else if k+1 == len(name) {
				if j+1 == len(route) {
					matched = true
				} else if route[j+1] == '.' {
					cut = true
				}
			}

			if param.Key != "" && paramSize < len(params) {
				params[paramSize] = param
				paramSize++
			}
		}

		if matched {
			index = i
		}
	}

	if matched {
		handler = (*w)[index].handler
		if paramSize > 0 {
			p = make(Params, 0, paramSize)
			for i := 0; i < paramSize; i++ {
				p = append(p, params[i])
			}
		}
	}

	return
}
