package casbin

import (
	"github.com/casbin/casbin/v2/util"
	"testing"
)

// TODO use "github.com/jeremywohl/flatten" dependency when pull request is merged
// https://github.com/jeremywohl/flatten/pull/12


type Obj struct {
	Name  string
	Owner string
}

func TestFlatten(t *testing.T) {
	request := map[string]interface{}{
		"r_sub": map[string]string{
			"firstname": "Fred",
			"lastname": "Brevart",
		},
		"r_obj": Obj{
			Name: "doc1",
			Owner: "owner47",
		},
		"r_action": "read",
	}

	req, err := Flatten(request, "", FuncMerger(func(top bool, key, subkey string) string {
		if top {
			key += subkey
		} else {
			key += "_" + util.ReplaceDots(subkey)
		}

		return key
	}))

	_, _ = req, err
}
