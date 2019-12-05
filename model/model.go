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
	"github.com/casbin/casbin/v2/rbac"
	"strconv"
	"strings"

	"github.com/casbin/casbin/v2/config"
	"github.com/casbin/casbin/v2/log"
	"github.com/casbin/casbin/v2/util"
)

type Model interface {
	AddDef(sec string, key string, value string) bool
	AddPolicy(sec string, ptype string, rule []string) (bool, int)
	BuildRoleLinks(rm rbac.RoleManager) error
	ClearPolicy()
	GetAssertionMap(key string) (AssertionMap, bool)
	GetAssertion(sec string, key string) (*Assertion, bool)
	GetFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) [][]string
	GetPolicy(sec string, ptype string) [][]string
	GetValuesForFieldInPolicy(sec string, ptype string, fieldIndex int) []string
	GetValuesForFieldInPolicyAllTypes(sec string, fieldIndex int) []string
	HasPolicy(sec string, ptype string, rule []string) bool
	LoadModel(path string) error
	LoadModelFromText(text string) error
	PrintModel()
	PrintPolicy()
	RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) (bool, []int)
	RemovePolicy(sec string, ptype string, rule []string) (bool, int)
}

// Model represents the whole access control model.
type AssertionModel map[string]AssertionMap

// AssertionMap is the collection of assertions, can be "r", "p", "g", "e", "m".
type AssertionMap map[string]*Assertion

var sectionNameMap = map[string]string{
	"r": "request_definition",
	"p": "policy_definition",
	"g": "role_definition",
	"e": "policy_effect",
	"m": "matchers",
}

func loadAssertion(model AssertionModel, cfg config.ConfigInterface, sec string, key string) bool {
	value := cfg.String(sectionNameMap[sec] + "::" + key)
	return model.AddDef(sec, key, value)
}


func (model AssertionModel) GetAssertionMap(key string) (AssertionMap, bool) {
	assertionMap, ok := model[key]

	return assertionMap, ok
}

func (model AssertionModel) GetAssertion(sec string, key string) (*Assertion, bool) {
	assertion, ok := model[sec][key]

	return assertion, ok
}

// AddDef adds an assertion to the model.
func (model AssertionModel) AddDef(sec string, key string, value string) bool {
	ast := Assertion{}
	ast.Key = key
	ast.Value = value
	ast.Policy = NewPolicy()

	if ast.Value == "" {
		return false
	}

	if sec == "r" || sec == "p" {
		ast.Tokens = strings.Split(ast.Value, ", ") // TODO sep ", " => "," (+ trim spaces)

		for i := range ast.Tokens {
			ast.Tokens[i] = key + "_" + util.ReplaceDots(ast.Tokens[i])
		}
	} else {
		ast.Value = util.RemoveComments(ast.Value)
	}

	_, ok := model[sec]
	if !ok {
		model[sec] = make(AssertionMap)
	}

	model[sec][key] = &ast
	return true
}

func getKeySuffix(i int) string {
	if i == 1 {
		return ""
	}

	return strconv.Itoa(i)
}

func loadSection(model AssertionModel, cfg config.ConfigInterface, sec string) {
	i := 1
	for {
		if !loadAssertion(model, cfg, sec, sec+getKeySuffix(i)) {
			break
		} else {
			i++
		}
	}
}

// NewModel creates an empty model.
func NewAssertionModel() AssertionModel {
	m := make(AssertionModel)
	return m
}

// NewModel creates a model from a .CONF file.
func NewAssertionModelFromFile(path string) (AssertionModel, error) {
	m := NewAssertionModel()

	err := m.LoadModel(path)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// NewModel creates a model from a string which contains model text.
func NewAssertionModelFromString(text string) (AssertionModel, error) {
	m := NewAssertionModel()

	err := m.LoadModelFromText(text)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// LoadModel loads the model from model CONF file.
func (model AssertionModel) LoadModel(path string) error {
	cfg, err := config.NewConfig(path)
	if err != nil {
		return err
	}

	loadSection(model, cfg, "r")
	loadSection(model, cfg, "p")
	loadSection(model, cfg, "e")
	loadSection(model, cfg, "m")

	loadSection(model, cfg, "g")

	return nil
}

// LoadModelFromText loads the model from the text.
func (model AssertionModel) LoadModelFromText(text string) error {
	cfg, err := config.NewConfigFromText(text)
	if err != nil {
		return err
	}

	loadSection(model, cfg, "r")
	loadSection(model, cfg, "p")
	loadSection(model, cfg, "e")
	loadSection(model, cfg, "m")

	loadSection(model, cfg, "g")

	return nil
}

// PrintModel prints the model to the log.
func (model AssertionModel) PrintModel() {
	log.LogPrint("Model:")
	for k, v := range model {
		for i, j := range v {
			log.LogPrintf("%s.%s: %s", k, i, j.Value)
		}
	}
}
