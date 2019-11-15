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
	"encoding/json"
	"errors"
	"strings"

	"github.com/casbin/casbin/v2/log"
	"github.com/casbin/casbin/v2/rbac"
)

type RulePart map[string]string
type Rule []RulePart

func (r Rule) String() string {
	tokens := []string{}

	for _, rulePart := range r {
		// TODO "value" => constant
		if v, ok := rulePart["value"] ; ok && len(r) == 1 {
			tokens = append(tokens, v)

			continue
		}

		t, err := json.Marshal(rulePart)
		if err != nil {
			// TODO
		}
		tokens = append(tokens, string(t))
	}

	// TODO separator "," => constant
	return strings.Join(tokens, ",")
}

func (r Rule) Equals(r2 Rule) bool {
	if len(r) != len(r2) {
		return false
	}

	for i, rulePart := range r {
		rulePart2 := r2[i]

		if len(rulePart) != len(rulePart2) {
			return false
		}

		for k, v := range rulePart {
			if v2, ok := rulePart2[k]; !ok || v != v2 {
				return false
			}
		}
	}

	return true
}

// Assertion represents an expression in a section of the model.
// For example: r = sub, obj, act
type Assertion struct {
	Key    string
	Value  string
	Tokens []string
	Policy []Rule
	RM     rbac.RoleManager
}

func (ast *Assertion) buildRoleLinks(rm rbac.RoleManager) error {
	ast.RM = rm
	count := strings.Count(ast.Value, "_")
	for _, rule := range ast.Policy {
		if count < 2 {
			return errors.New("the number of \"_\" in role definition should be at least 2")
		}
		if len(rule) < count {
			return errors.New("grouping policy elements do not meet role definition")
		}

		ruleStrings := make([]string, len(rule))
		for i, rulePart := range rule {
			v, ok := rulePart["value"] // TODO "value" => constant
			if !ok {
				// TODO
			}
			ruleStrings[i] = v
		}

		if count == 2 {
			err := ast.RM.AddLink(ruleStrings[0], ruleStrings[1])
			if err != nil {
				return err
			}
		} else if count == 3 {
			err := ast.RM.AddLink(ruleStrings[0], ruleStrings[1], ruleStrings[2])
			if err != nil {
				return err
			}
		} else if count == 4 {
			err := ast.RM.AddLink(ruleStrings[0], ruleStrings[1], ruleStrings[2], ruleStrings[3])
			if err != nil {
				return err
			}
		}
	}

	log.LogPrint("Role links for: " + ast.Key)
	return ast.RM.PrintRoles()
}
