package casbin

import "strings"

func keyMatch(key1 string, key2 string) bool {
	i := strings.Index(key2, "*")
	if i == -1 {
		return key1 == key2
	}

	if len(key1) > i {
		return key1[:i] == key2[:i]
	} else {
		return key1 == key2[:i]
	}
}

func keyMatchFunc(args ...interface{}) (interface{}, error) {
	name1 := args[0].(string)
	name2 := args[1].(string)

	return (bool)(keyMatch(name1, name2)), nil
}