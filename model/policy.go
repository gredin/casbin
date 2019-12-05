// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package model

import (
	"github.com/casbin/casbin/v2/log"
	"github.com/casbin/casbin/v2/rbac"
	"github.com/casbin/casbin/v2/util"
	"github.com/emirpasic/gods/maps/linkedhashmap"
)

type Policy struct {
	rules         *linkedhashmap.Map
	autoincrement int
	iterator      linkedhashmap.Iterator
}

func NewPolicy() *Policy {
	rules := linkedhashmap.New()

	return &Policy{
		rules:         rules,
		autoincrement: 0,
		iterator:      rules.Iterator(),
	}
}

func (p *Policy) String() string {
	return p.rules.String()
}

func (p *Policy) GetRules() [][]string {
	values := make([][]string, p.rules.Size())
	i := 0
	var ok bool
	for p.iterator.Begin(); p.iterator.Next(); {
		values[i], ok = p.iterator.Value().([]string)
		if !ok {
			panic("expected []string type")
		}
		i++
	}
	return values
}

func (p *Policy) Begin() {
	p.iterator.Begin()
}

func (p *Policy) Next() bool {
	return p.iterator.Next()
}

func (p *Policy) GetNext() (int, []string) {
	k, ok := p.iterator.Key().(int)
	if !ok {
		panic("expected int type")
	}

	v, ok := p.iterator.Value().([]string)
	if !ok {
		panic("expected []string type")
	}

	return k, v
}

func (p *Policy) Put(rule []string) int {
	i := p.autoincrement
	p.rules.Put(i, rule)
	p.autoincrement++

	return i
}

func (p *Policy) Get(ruleId int) ([]string, bool) {
	r, ok := p.rules.Get(ruleId)
	if !ok {
		return []string{}, false
	}

	rule, ok := r.([]string)
	if !ok {
		panic("expected []string type")
	}

	return rule, true
}

func (p *Policy) Len() int {
	return p.rules.Size()
}

func (p *Policy) Remove(i int) {
	p.rules.Remove(i)
}

// BuildRoleLinks initializes the roles in RBAC.
func (model AssertionModel) BuildRoleLinks(rm rbac.RoleManager) error {
	for _, ast := range model["g"] {
		err := ast.buildRoleLinks(rm)
		if err != nil {
			return err
		}
	}

	return nil
}

// PrintPolicy prints the policy to log.
func (model AssertionModel) PrintPolicy() {
	log.LogPrint("Policy:")
	for key, ast := range model["p"] {
		log.LogPrint(key, ": ", ast.Value, ": ", ast.Policy)
	}

	for key, ast := range model["g"] {
		log.LogPrint(key, ": ", ast.Value, ": ", ast.Policy)
	}
}

// ClearPolicy clears all current policy.
func (model AssertionModel) ClearPolicy() {
	for _, ast := range model["p"] {
		ast.Policy = NewPolicy()
	}

	for _, ast := range model["g"] {
		ast.Policy = NewPolicy()
	}
}

// GetPolicy gets all rules in a policy.
func (model AssertionModel) GetPolicy(sec string, ptype string) [][]string {
	return model[sec][ptype].Policy.GetRules()
}

// GetFilteredPolicy gets rules based on field filters from a policy.
func (model AssertionModel) GetFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) [][]string {
	res := [][]string{}

	policy := model[sec][ptype].Policy

	for policy.Begin(); policy.Next(); {
		_, rule := policy.GetNext()

		matched := true
		for i, fieldValue := range fieldValues {
			if fieldValue != "" && rule[fieldIndex+i] != fieldValue {
				matched = false
				break
			}
		}

		if matched {
			res = append(res, rule)
		}
	}

	return res
}

// TODO can be optimized (use sqlite db) - but this is MODEL package, not ENFORCER (...?)
// HasPolicy determines whether a model has the specified policy rule.
func (model AssertionModel) HasPolicy(sec string, ptype string, rule []string) bool {
	policy := model[sec][ptype].Policy

	for policy.Begin(); policy.Next(); {
		_, r := policy.GetNext()

		if util.ArrayEquals(rule, r) {
			return true
		}
	}

	return false
}

// AddPolicy adds a policy rule to the model.
func (model AssertionModel) AddPolicy(sec string, ptype string, rule []string) (bool, int) {
	if !model.HasPolicy(sec, ptype, rule) {
		ruleId := model[sec][ptype].Policy.Put(rule)

		return true, ruleId
	}
	return false, 0
}

// RemovePolicy removes a policy rule from the model.
func (model AssertionModel) RemovePolicy(sec string, ptype string, rule []string) (bool, int) {
	policy := model[sec][ptype].Policy

	for policy.Begin(); policy.Next(); {
		i, r := policy.GetNext()

		if util.ArrayEquals(rule, r) {
			policy.Remove(i)

			return true, i
		}
	}

	return false, 0
}

// RemoveFilteredPolicy removes policy rules based on field filters from the model.
func (model AssertionModel) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) (bool, []int) {
	foundIndexes := []int{}
	res := false

	policy := model[sec][ptype].Policy

	for policy.Begin(); policy.Next(); {
		i, rule := policy.GetNext()

		matched := true
		for j, fieldValue := range fieldValues {
			if fieldValue != "" && rule[fieldIndex+j] != fieldValue {
				matched = false
				break
			}
		}

		if matched {
			res = true
			foundIndexes = append(foundIndexes, i)
		}
	}

	// TODO efficiency
	for _, i := range foundIndexes {
		policy.Remove(i)
	}

	return res, foundIndexes
}

// GetValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
func (model AssertionModel) GetValuesForFieldInPolicy(sec string, ptype string, fieldIndex int) []string {
	values := []string{}

	policy := model[sec][ptype].Policy

	for policy.Begin(); policy.Next(); {
		_, rule := policy.GetNext()

		values = append(values, rule[fieldIndex])
	}

	util.ArrayRemoveDuplicates(&values)

	return values
}

// GetValuesForFieldInPolicyAllTypes gets all values for a field for all rules in a policy of all ptypes, duplicated values are removed.
func (model AssertionModel) GetValuesForFieldInPolicyAllTypes(sec string, fieldIndex int) []string {
	values := []string{}

	for ptype := range model[sec] {
		values = append(values, model.GetValuesForFieldInPolicy(sec, ptype, fieldIndex)...)
	}

	util.ArrayRemoveDuplicates(&values)

	return values
}
