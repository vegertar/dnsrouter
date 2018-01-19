package dnsrouter

import (
	"strings"
	"testing"
)

func TestWildcardTree_addRoute(t *testing.T) {
	tc := []struct {
		name  string
		error string
	}{
		{name: ".com.a", error: "only wildcard names are permitted"},
		{name: ".:com.a", error: "only wildcard names are permitted"},
		{name: ".:a.:b.c.d.e", error: "only wildcard names are permitted"},
		{name: ".a.*a"},
		{name: "*a", error: "must appear behind the '.'"},
		{name: ".a.b.:c.*d"},
		{name: ".*a.b", error: "'*' has to be the last label"},
		{name: ".ab:c.d", error: "only wildcard names are permitted"},
	}

	tree := new(wildcardTree)
	for _, c := range tc {
		func(name, error string) {
			defer func() {
				if s := recover(); s != nil {
					if error == "" || !strings.Contains(s.(string), error) {
						t.Errorf("%s: expected error %s, got %s", name, error, s)
					}
				} else if error != "" {
					t.Errorf("%s: expected error %s, got nil", name, error)
				}
			}()
			tree.addRoute(name, false, nodeHandlerElement{})
		}(c.name, c.error)
	}

	nameOrder := []string{
		".a.b.:c.*d",
		".a.*a",
	}
	if len(nameOrder) != tree.Len() {
		t.Errorf("expected length %d, got %d", len(nameOrder), tree.Len())
	}
	for i, s := range nameOrder {
		if name := (*tree)[i].name; name != s {
			t.Errorf("%d: expected name %s, got %s", i, s, name)
		}
	}
}

func TestWildcardTree_getValue(t *testing.T) {
	tree := new(wildcardTree)

	routes := []string{
		".src.*filename",
		".files.:dir.*filename",
		".files2.:dir.*filename",
		".files2.:dir.:dir2.*filename",
	}
	for _, route := range routes {
		tree.addRoute(route, false, fakeHandler(route))
	}

	// unlike callAll expansion in tree.go, expansion here would never include leading '.'
	checkRequests(t, tree, testRequests{
		{".src", true, "", nil, true},
		{".src.", true, "", nil, false},
		{".src.*", false, ".src.*filename", Params{Param{"filename", "*"}}, false},
		{".src.some.file.png", false, ".src.*filename", Params{Param{"filename", "some.file.png"}}, false},
		{".files.js.inc.framework.js", false, ".files.:dir.*filename", Params{Param{"dir", "js"}, Param{"filename", "inc.framework.js"}}, false},
		{".files2.js.inc.framework.js", false, ".files2.:dir.:dir2.*filename", Params{Param{"dir", "js"}, Param{"dir2", "inc"}, Param{"filename", "framework.js"}}, false},
	})

}
