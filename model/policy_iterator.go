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

type PolicyIterator interface {
	Begin()
	Next() bool
	Get() ([]string, bool)
	Len() int
}

type CompleteIterator struct {
	policy *Policy
}

func NewCompleteIterator(policy *Policy) *CompleteIterator {
	return &CompleteIterator{policy: policy}
}

func (iterator *CompleteIterator) Begin() {
	iterator.policy.Begin()
}

func (iterator *CompleteIterator) Next() bool {
	return iterator.policy.Next()
}

func (iterator *CompleteIterator) Get() ([]string, bool) {
	_, rule := iterator.policy.GetNext()

	return rule, true
}

func (iterator *CompleteIterator) Len() int {
	return iterator.policy.Len()
}

type PartialIterator struct {
	ruleIds *[]int
	policy  *Policy
	index   int
}

func NewPartialIterator(ruleIds *[]int, policy *Policy) *PartialIterator {
	return &PartialIterator{
		ruleIds: ruleIds,
		policy:  policy,
		index:   -1,
	}
}

func (iterator *PartialIterator) Begin() {
	iterator.index = -1
}

func (iterator *PartialIterator) Next() bool {
	iterator.index++

	return iterator.index < len(*iterator.ruleIds)
}

func (iterator *PartialIterator) Get() ([]string, bool) {
	if iterator.index >= len(*iterator.ruleIds) {
		return []string{}, false
	}

	ruleId := (*iterator.ruleIds)[iterator.index]

	return iterator.policy.Get(ruleId)
}

func (iterator *PartialIterator) Len() int {
	return len(*iterator.ruleIds)
}
