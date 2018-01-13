// Copyright 2013 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// at https://github.com/julienschmidt/httprouter/blob/master.LICENSE

package dnsrouter

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func printChildren(n *node, prefix string) {
	fmt.Printf(" %02d:%02d %s%s[%d] %v %t %d \r\n", n.priority, n.maxParams, prefix, n.name, len(n.children), n.handler, n.wildChild, n.nType)
	for l := len(n.name); l > 0; l-- {
		prefix += " "
	}
	for _, child := range n.children {
		printChildren(child, prefix)
	}
}

// Used as a workaround since we can't compare functions or their addresses
var fakeHandlerValue string

func fakeHandler(val string) nodeHandlerElement {
	return nodeHandlerElement{
		Handler: HandlerFunc(func(ResponseWriter, *Request) {
			fakeHandlerValue = val
		}),
	}
}

type testRequests []struct {
	name       string
	nilHandler bool
	route      string
	ps         Params
	cut        bool
}

func checkRequests(t *testing.T, tree *node, requests testRequests) {
	for _, request := range requests {
		handler, ps, cut := tree.getValue(request.name)

		if handler == nil {
			if !request.nilHandler {
				t.Errorf("handle mismatch for route '%s': Expected non-nil handle", request.name)
			}
		} else if request.nilHandler {
			t.Errorf("handle mismatch for route '%s': Expected nil handle", request.name)
		} else {
			handler.ServeDNS(nil, nil)
			if fakeHandlerValue != request.route {
				t.Errorf("handle mismatch for route '%s': Wrong handle (%s != %s)", request.name, fakeHandlerValue, request.route)
			}
		}

		if !reflect.DeepEqual(ps, request.ps) {
			t.Errorf("Params mismatch for route '%s'", request.name)
		}
		if cut != request.cut {
			t.Errorf("cut(%v) mismatch for route '%s'", request.cut, request.name)
		}
	}
}

func checkPriorities(t *testing.T, n *node) uint32 {
	var prio uint32
	for i := range n.children {
		prio += checkPriorities(t, n.children[i])
	}

	if n.handler != nil {
		prio++
	}

	if n.priority != prio {
		t.Errorf(
			"priority mismatch for node '%s': is %d, should be %d",
			n.name, n.priority, prio,
		)
	}

	return prio
}

func checkMaxParams(t *testing.T, n *node) uint8 {
	var maxParams uint8
	for i := range n.children {
		params := checkMaxParams(t, n.children[i])
		if params > maxParams {
			maxParams = params
		}
	}
	if n.nType > root && !n.wildChild {
		maxParams++
	}

	if n.maxParams != maxParams {
		t.Errorf(
			"maxParams mismatch for node '%s': is %d, should be %d",
			n.name, n.maxParams, maxParams,
		)
	}

	return maxParams
}

func TestCountParams(t *testing.T) {
	if countParams(".name.:param1.static.*catch-all") != 2 {
		t.Fail()
	}
	if countParams(strings.Repeat(".:param", 256)) != 255 {
		t.Fail()
	}
}

func TestTreeAddAndGet(t *testing.T) {
	tree := &node{}

	routes := [...]string{
		".hi",
		".contact",
		".co",
		".c",
		".a",
		".ab",
		".doc.",
		".doc.go_faq.html",
		".doc.go1.html",
		".α",
		".β",
	}
	for _, route := range routes {
		tree.addRoute(route, false, fakeHandler(route))
	}

	//printChildren(tree, "")

	checkRequests(t, tree, testRequests{
		{".a", false, ".a", nil, false},
		{".", true, "", nil, false},
		{".hi", false, ".hi", nil, false},
		{".contact", false, ".contact", nil, false},
		{".co", false, ".co", nil, false},
		{".con", true, "", nil, false},  // key mismatch
		{".cona", true, "", nil, false}, // key mismatch
		{".no", true, "", nil, false},   // no matching child
		{".ab", false, ".ab", nil, false},
		{".α", false, ".α", nil, false},
		{".β", false, ".β", nil, false},
		{".doc", true, "", nil, true},
		{".doc.go1", true, "", nil, true},
	})

	checkPriorities(t, tree)
	checkMaxParams(t, tree)
}

func TestTreeWildcard(t *testing.T) {
	tree := &node{}

	routes := [...]string{
		".",
		".cmd.:tool.:sub",
		".cmd.:tool.",
		".src.*filename",
		".search.",
		".search.:query",
		".user_:name",
		".user_:name.about",
		".files.:dir.*filename",
		".doc.",
		".doc.go_faq.html",
		".doc.go1.html",
		".info.:user.public",
		".info.:user.project.:project",
	}
	for _, route := range routes {
		tree.addRoute(route, false, fakeHandler(route))
	}

	//printChildren(tree, "")

	checkRequests(t, tree, testRequests{
		{".", false, ".", nil, false},
		{".cmd.test.", false, ".cmd.:tool.", Params{Param{"tool", "test"}}, false},
		{".cmd.test", true, "", Params{Param{"tool", "test"}}, true},
		{".cmd.test.3", false, ".cmd.:tool.:sub", Params{Param{"tool", "test"}, Param{"sub", "3"}}, false},
		{".src.", false, ".src.*filename", Params{Param{"filename", "."}}, false},
		{".src.some.file.png", false, ".src.*filename", Params{Param{"filename", ".some.file.png"}}, false},
		{".search.", false, ".search.", nil, false},
		{".search.someth!ng+in+ünìcodé", false, ".search.:query", Params{Param{"query", "someth!ng+in+ünìcodé"}}, false},
		{".search.someth!ng+in+ünìcodé.", true, "", Params{Param{"query", "someth!ng+in+ünìcodé"}}, false},
		{".user_gopher", false, ".user_:name", Params{Param{"name", "gopher"}}, false},
		{".user_gopher.about", false, ".user_:name.about", Params{Param{"name", "gopher"}}, false},
		{".files.js.inc.framework.js", false, ".files.:dir.*filename", Params{Param{"dir", "js"}, Param{"filename", ".inc.framework.js"}}, false},
		{".info.gordon.public", false, ".info.:user.public", Params{Param{"user", "gordon"}}, false},
		{".info.gordon.project.go", false, ".info.:user.project.:project", Params{Param{"user", "gordon"}, Param{"project", "go"}}, false},
	})

	checkPriorities(t, tree)
	checkMaxParams(t, tree)
}

func catchPanic(testFunc func()) (recv interface{}) {
	defer func() {
		recv = recover()
	}()

	testFunc()
	return
}

type testRoute struct {
	name     string
	conflict bool
}

func testRoutes(t *testing.T, routes []testRoute) {
	tree := &node{}

	for _, route := range routes {
		recv := catchPanic(func() {
			tree.addRoute(route.name, false, nodeHandlerElement{})
		})

		if route.conflict {
			if recv == nil {
				t.Errorf("no panic for conflicting route '%s'", route.name)
			}
		} else if recv != nil {
			t.Errorf("unexpected panic for route '%s': %v", route.name, recv)
		}
	}

	//printChildren(tree, "")
}

func TestTreeWildcardConflict(t *testing.T) {
	routes := []testRoute{
		{".cmd.:tool.:sub", false},
		{".cmd.vet", true},
		{".src.*filename", false},
		{".src.*filenamex", true},
		{".src.", true},
		{".src1.", false},
		{".src1.*filename", true},
		{".src2*filename", true},
		{".search.:query", false},
		{".search.invalid", true},
		{".user_:name", false},
		{".user_x", true},
		{".user_:name", true},
		{".id:id", false},
		{".id.:id", true},
	}
	testRoutes(t, routes)
}

func TestTreeChildConflict(t *testing.T) {
	routes := []testRoute{
		{".cmd.vet", false},
		{".cmd.:tool.:sub", true},
		{".src.AUTHORS", false},
		{".src.*filename", true},
		{".user_x", false},
		{".user_:name", true},
		{".id.:id", false},
		{".id:id", true},
		{".:id", true},
		{".*filename", true},
	}
	testRoutes(t, routes)
}

func TestTreeDupliateName(t *testing.T) {
	tree := &node{}

	routes := [...]string{
		".",
		".doc.",
		".src.*filename",
		".search.:query",
		".user_:name",
	}
	for _, route := range routes {
		recv := catchPanic(func() {
			tree.addRoute(route, false, fakeHandler(route))
		})
		if recv != nil {
			t.Fatalf("panic inserting route '%s': %v", route, recv)
		}

		// Add again
		recv = catchPanic(func() {
			tree.addRoute(route, false, nodeHandlerElement{})
		})
		if recv == nil {
			t.Fatalf("no panic while inserting duplicate route '%s", route)
		}

		// Add again
		recv = catchPanic(func() {
			tree.addRoute(route, true, nodeHandlerElement{})
		})
		if recv != nil {
			t.Fatalf("panic inserting duplicate route '%s': %v", route, recv)
		}

	}

	//printChildren(tree, "")

	checkRequests(t, tree, testRequests{
		{".", false, ".", nil, false},
		{".doc.", false, ".doc.", nil, false},
		{".src.some.file.png", false, ".src.*filename", Params{Param{"filename", ".some.file.png"}}, false},
		{".search.someth!ng+in+ünìcodé", false, ".search.:query", Params{Param{"query", "someth!ng+in+ünìcodé"}}, false},
		{".user_gopher", false, ".user_:name", Params{Param{"name", "gopher"}}, false},
	})
}

func TestEmptyWildcardName(t *testing.T) {
	tree := &node{}

	routes := [...]string{
		".user:",
		".user:.",
		".cmd.:.",
		".src.*",
	}
	for _, route := range routes {
		recv := catchPanic(func() {
			tree.addRoute(route, false, nodeHandlerElement{})
		})
		if recv == nil {
			t.Fatalf("no panic while inserting route with empty wildcard name '%s", route)
		}
	}
}

func TestTreeCatchAllConflict(t *testing.T) {
	routes := []testRoute{
		{".src.*filename.x", true},
		{".src2.", false},
		{".src2.*filename.x", true},
	}
	testRoutes(t, routes)
}

func TestTreeCatchAllConflictRoot(t *testing.T) {
	routes := []testRoute{
		{".", false},
		{".*filename", true},
	}
	testRoutes(t, routes)
}

func TestTreeDoubleWildcard(t *testing.T) {
	const panicMsg = "only one wildcard per name segment is allowed"

	routes := [...]string{
		".:foo:bar",
		".:foo:bar.",
		".:foo*bar",
	}

	for _, route := range routes {
		tree := &node{}
		recv := catchPanic(func() {
			tree.addRoute(route, false, nodeHandlerElement{})
		})

		if rs, ok := recv.(string); !ok || !strings.HasPrefix(rs, panicMsg) {
			t.Fatalf(`"Expected panic "%s" for route '%s', got "%v"`, panicMsg, route, recv)
		}
	}
}

func TestTreeFindCaseInsensitiveName(t *testing.T) {
	tree := &node{}

	routes := [...]string{
		".hi",
		".b.",
		".ABC.",
		".search.:query",
		".cmd.:tool.",
		".src.*filename",
		".x",
		".x.y",
		".y.",
		".y.z",
		".0.:id",
		".0.:id.1",
		".1.:id.",
		".1.:id.2",
		".aa",
		".a.",
		".doc",
		".doc.go_faq.html",
		".doc.go1.html",
		".doc.go.away",
		".no.a",
		".no.b",
		".Π",
		".u.apfêl.",
		".u.äpfêl.",
		".u.öpfêl",
		".v.Äpfêl.",
		".v.Öpfêl",
		".w.♬",  // 3 byte
		".w.♭.", // 3 byte, last byte differs
		".w.𠜎",  // 4 byte
		".w.𠜏.", // 4 byte
	}

	for _, route := range routes {
		recv := catchPanic(func() {
			tree.addRoute(route, false, fakeHandler(route))
		})
		if recv != nil {
			t.Fatalf("panic inserting route '%s': %v", route, recv)
		}
	}

	for _, route := range routes {
		out, found := tree.findCaseInsensitiveName(route)
		if !found {
			t.Errorf("Route '%s' not found!", route)
		} else if string(out) != route {
			t.Errorf("Wrong result for route '%s': %s", route, string(out))
		}
	}

	tests := []struct {
		in    string
		out   string
		found bool
		slash bool
	}{
		{".HI", ".hi", true, false},
		{".HI.", ".hi", true, true},
		{".B", ".b.", true, true},
		{".B.", ".b.", true, false},
		{".abc", ".ABC.", true, true},
		{".abc.", ".ABC.", true, false},
		{".aBc", ".ABC.", true, true},
		{".aBc.", ".ABC.", true, false},
		{".abC", ".ABC.", true, true},
		{".abC.", ".ABC.", true, false},
		{".SEARCH.QUERY", ".search.QUERY", true, false},
		{".SEARCH.QUERY.", ".search.QUERY", true, true},
		{".CMD.TOOL.", ".cmd.TOOL.", true, false},
		{".CMD.TOOL", ".cmd.TOOL.", true, true},
		{".SRC.FILE.NAME", ".src.FILE.NAME", true, false},
		{".x.Y", ".x.y", true, false},
		{".x.Y.", ".x.y", true, true},
		{".X.y", ".x.y", true, false},
		{".X.y.", ".x.y", true, true},
		{".X.Y", ".x.y", true, false},
		{".X.Y.", ".x.y", true, true},
		{".Y.", ".y.", true, false},
		{".Y", ".y.", true, true},
		{".Y.z", ".y.z", true, false},
		{".Y.z.", ".y.z", true, true},
		{".Y.Z", ".y.z", true, false},
		{".Y.Z.", ".y.z", true, true},
		{".y.Z", ".y.z", true, false},
		{".y.Z.", ".y.z", true, true},
		{".Aa", ".aa", true, false},
		{".Aa.", ".aa", true, true},
		{".AA", ".aa", true, false},
		{".AA.", ".aa", true, true},
		{".aA", ".aa", true, false},
		{".aA.", ".aa", true, true},
		{".A.", ".a.", true, false},
		{".A", ".a.", true, true},
		{".DOC", ".doc", true, false},
		{".DOC.", ".doc", true, true},
		{".NO", "", false, true},
		{".DOC.GO", "", false, true},
		{".π", ".Π", true, false},
		{".π.", ".Π", true, true},
		{".u.ÄPFÊL.", ".u.äpfêl.", true, false},
		{".u.ÄPFÊL", ".u.äpfêl.", true, true},
		{".u.ÖPFÊL.", ".u.öpfêl", true, true},
		{".u.ÖPFÊL", ".u.öpfêl", true, false},
		{".v.äpfêL.", ".v.Äpfêl.", true, false},
		{".v.äpfêL", ".v.Äpfêl.", true, true},
		{".v.öpfêL.", ".v.Öpfêl", true, true},
		{".v.öpfêL", ".v.Öpfêl", true, false},
		{".w.♬.", ".w.♬", true, true},
		{".w.♭", ".w.♭.", true, true},
		{".w.𠜎.", ".w.𠜎", true, true},
		{".w.𠜏", ".w.𠜏.", true, true},
	}

	for _, test := range tests {
		out, found := tree.findCaseInsensitiveName(test.in)
		if test.slash {
			if found { // test needs a trailingSlash fix. It must not be found!
				t.Errorf("Found without fixTrailingSlash: %s; got %s", test.in, string(out))
			}
		} else {
			if found != test.found || (found && (string(out) != test.out)) {
				t.Errorf("Wrong result for '%s': got %s, %t; want %s, %t",
					test.in, string(out), found, test.out, test.found)
				return
			}
		}
	}
}

func TestTreeInvalidNodeType(t *testing.T) {
	const panicMsg = "invalid node type"

	tree := &node{}
	tree.addRoute(".", false, fakeHandler("."))
	tree.addRoute(".:page", false, fakeHandler(".:page"))

	// set invalid node type
	tree.children[0].nType = 42

	// normal lookup
	recv := catchPanic(func() {
		tree.getValue(".test")
	})
	if rs, ok := recv.(string); !ok || rs != panicMsg {
		t.Fatalf("Expected panic '"+panicMsg+"', got '%v'", recv)
	}

	// case-insensitive lookup
	recv = catchPanic(func() {
		tree.findCaseInsensitiveName(".test")
	})
	if rs, ok := recv.(string); !ok || rs != panicMsg {
		t.Fatalf("Expected panic '"+panicMsg+"', got '%v'", recv)
	}
}

func TestTreeWildcardConflictEx(t *testing.T) {
	conflicts := [...]struct {
		route        string
		segName      string
		existName    string
		existSegName string
	}{
		{".who.are.foo", ".foo", `.who.are.\*you`, `.\*you`},
		{".who.are.foo.", ".foo.", `.who.are.\*you`, `.\*you`},
		{".who.are.foo.bar", ".foo.bar", `.who.are.\*you`, `.\*you`},
		{".conxxx", "xxx", `.con:tact`, `:tact`},
		{".conooo.xxx", "ooo", `.con:tact`, `:tact`},
	}

	for _, conflict := range conflicts {
		// I have to re-create a 'tree', because the 'tree' will be
		// in an inconsistent state when the loop recovers from the
		// panic which threw by 'addRoute' function.
		tree := &node{}
		routes := [...]string{
			".con:tact",
			".who.are.*you",
			".who.foo.hello",
		}

		for _, route := range routes {
			tree.addRoute(route, false, fakeHandler(route))
		}

		recv := catchPanic(func() {
			tree.addRoute(conflict.route, false, fakeHandler(conflict.route))
		})

		if !regexp.MustCompile(fmt.Sprintf("'%s' in new name .* conflicts with existing wildcard '%s' in existing prefix '%s'", conflict.segName, conflict.existSegName, conflict.existName)).MatchString(fmt.Sprint(recv)) {
			t.Fatalf("invalid wildcard conflict error (%v)", recv)
		}
	}
}
