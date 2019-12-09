package model

import (
	"testing"
)

func testNoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("no error expected (%s)", err.Error())
	}
}

func testHasPolicy(t *testing.T, m Model, rule []string, expected bool) {
	t.Helper()

	result := m.HasPolicy("p", "p", rule)

	if result != expected {
		t.Errorf("HasPolicy result: %t, supposed to be %t", result, expected)
	}
}

func TestModelDB_HasPolicy(t *testing.T) {
	m, err := NewModelDBFromFile("../examples/basic_model.conf")
	testNoError(t, err)

	m.AddPolicy("p", "p", []string{"sub1", "obj1", "act1"})
	m.AddPolicy("p", "p", []string{"sub3", "obj3", "act3"})

	testHasPolicy(t, m, []string{"sub1", "obj1", "act1"}, true)
	testHasPolicy(t, m, []string{"sub2", "obj2", "act2"}, false)
	testHasPolicy(t, m, []string{"sub3", "obj3", "act3"}, true)

	m.AddPolicy("p", "p", []string{"sub2", "obj2", "act2"})
	m.RemovePolicy("p", "p", []string{"sub3", "obj3", "act3"})

	testHasPolicy(t, m, []string{"sub1", "obj1", "act1"}, true)
	testHasPolicy(t, m, []string{"sub2", "obj2", "act2"}, true)
	testHasPolicy(t, m, []string{"sub3", "obj3", "act3"}, false)
}
