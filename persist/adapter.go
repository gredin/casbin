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

package persist

import (
	"encoding/json"
	"strings"

	"github.com/casbin/casbin/v2/model"
)

func SplitLine(line string) []string {
	tokens := []string{}

	cursor := 0
	for i := 0; i < len(line); i++ {
		if line[i] == ',' {
			tokens = append(tokens, line[cursor:i])

			cursor = i+1

			continue
		}

		if line[i] == '{' {
			cursor = i

			for i < len(line) {
				if line[i] == '}' {
					break
				}

				i++
			}
		}
	}

	if cursor < len(line) {
		tokens = append(tokens, line[cursor:])
	}

	return tokens
}

// LoadPolicyLine loads a text line as a policy rule to model.
func LoadPolicyLine(line string, mod model.Model) {
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}

	tokens := SplitLine(line)
	rule := model.Rule{}
	for _, t := range tokens[1:] {
		token := strings.TrimSpace(t)

		if !(token[0] == '{' && token[len(token)-1] == '}') {
			// TODO "value" => constant
			rule = append(rule, map[string]string{"value": token})

			continue
		}

		rulePart := map[string]string{}
		err := json.Unmarshal([]byte(token), &rulePart)
		if err != nil {
			// TODO
			println(err.Error())
		}
		rule = append(rule, rulePart)
	}

	key := tokens[0]
	sec := key[:1]
	mod[sec][key].Policy = append(mod[sec][key].Policy, rule)
}

// Adapter is the interface for Casbin adapters.
type Adapter interface {
	// LoadPolicy loads all policy rules from the storage.
	LoadPolicy(model model.Model) error
	// SavePolicy saves all policy rules to the storage.
	SavePolicy(model model.Model) error

	// AddPolicy adds a policy rule to the storage.
	// This is part of the Auto-Save feature.
	AddPolicy(sec string, ptype string, rule model.Rule) error
	// RemovePolicy removes a policy rule from the storage.
	// This is part of the Auto-Save feature.
	RemovePolicy(sec string, ptype string, rule model.Rule) error
	// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
	// This is part of the Auto-Save feature.
	RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error
}
