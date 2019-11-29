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
	"fmt"
	"github.com/casbin/casbin/v2/rbac"
	"github.com/casbin/casbin/v2/util"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

type Function struct {
	Declaration *exprpb.Decl
	Overloads   []*functions.Overload
}

// FunctionMap represents the collection of Function.
type FunctionMap map[string]Function

// TODO should be private because all funcs should provided at instantiation of Enforcer
func (fm FunctionMap) AddFunction(declaration *exprpb.Decl, overloads []*functions.Overload) {
	fm[declaration.Name] = Function{
		Declaration: declaration,
		Overloads:   overloads,
	}
}

// TODO should be private because all funcs should provided at instantiation of Enforcer
func (fm FunctionMap) AddFunctionWithSingleOverload(declaration *exprpb.Decl, overload *functions.Overload) {
	fm[declaration.Name] = Function{
		Declaration: declaration,
		Overloads:   []*functions.Overload{overload},
	}
}

// LoadFunctionMap loads an initial function map.
func LoadFunctionMap() FunctionMap {
	fm := make(FunctionMap)

	fm.AddFunctionWithSingleOverload(decls.NewFunction("keyMatch",
		decls.NewOverload("keyMatch_string_string", []*exprpb.Type{decls.String, decls.String}, decls.Bool)),
		&functions.Overload{
			Operator: "keyMatch_string_string",
			Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
				val1 := lhs.(types.String).Value().(string)
				val2 := rhs.(types.String).Value().(string)

				return types.Bool(util.KeyMatch(val1, val2))
			}})

	fm.AddFunctionWithSingleOverload(decls.NewFunction("keyMatch2",
		decls.NewOverload("keyMatch2_string_string",
			[]*exprpb.Type{decls.String, decls.String}, decls.Bool)),
		&functions.Overload{
			Operator: "keyMatch2_string_string",
			Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
				val1 := lhs.(types.String).Value().(string)
				val2 := rhs.(types.String).Value().(string)

				return types.Bool(util.KeyMatch2(val1, val2))
			}})

	fm.AddFunctionWithSingleOverload(
		decls.NewFunction("keyMatch3",
			decls.NewOverload("keyMatch3_string_string",
				[]*exprpb.Type{decls.String, decls.String}, decls.Bool)),
		&functions.Overload{
			Operator: "keyMatch3_string_string",
			Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
				val1 := lhs.(types.String).Value().(string)
				val2 := rhs.(types.String).Value().(string)

				return types.Bool(util.KeyMatch3(val1, val2))
			}})

	fm.AddFunctionWithSingleOverload(
		decls.NewFunction("keyMatch4",
			decls.NewOverload("keyMatch4_string_string",
				[]*exprpb.Type{decls.String, decls.String}, decls.Bool)),
		&functions.Overload{
			Operator: "keyMatch4_string_string",
			Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
				val1 := lhs.(types.String).Value().(string)
				val2 := rhs.(types.String).Value().(string)

				return types.Bool(util.KeyMatch4(val1, val2))
			}})

	fm.AddFunctionWithSingleOverload(
		decls.NewFunction("regexMatch",
			decls.NewOverload("regexMatch_string_string",
				[]*exprpb.Type{decls.String, decls.String}, decls.Bool)),
		&functions.Overload{
			Operator: "regexMatch_string_string",
			Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
				val1 := lhs.(types.String).Value().(string)
				val2 := rhs.(types.String).Value().(string)

				return types.Bool(util.RegexMatch(val1, val2))
			}})

	fm.AddFunctionWithSingleOverload(
		decls.NewFunction("ipMatch",
			decls.NewOverload("ipMatch_string_string",
				[]*exprpb.Type{decls.String, decls.String}, decls.Bool)),
		&functions.Overload{
			Operator: "ipMatch_string_string",
			Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
				val1 := lhs.(types.String).Value().(string)
				val2 := rhs.(types.String).Value().(string)

				return types.Bool(util.IPMatch(val1, val2))
			}})

	return fm
}

// GenerateGFunction is the factory method of the g(_, _) function.
func GenerateGFunction(key string, rm rbac.RoleManager) Function {
	overloadId2Args := fmt.Sprintf("%s_string_string", key)
	overloadId3Args := fmt.Sprintf("%s_string_string_string", key)

	return Function{
		Declaration: decls.NewFunction(key,
			decls.NewOverload(overloadId2Args,
				[]*exprpb.Type{decls.String, decls.String}, decls.Bool),
			decls.NewOverload(overloadId3Args,
				[]*exprpb.Type{decls.String, decls.String, decls.String}, decls.Bool)),
		Overloads: []*functions.Overload{
			{
				Operator: overloadId2Args,
				Binary: func(val1 ref.Val, val2 ref.Val) ref.Val {
					name1 := val1.(types.String).Value().(string)
					name2 := val2.(types.String).Value().(string)

					if rm == nil {
						return types.Bool(name1 == name2)
					}

					res, _ := rm.HasLink(name1, name2)

					return types.Bool(res)
				}},
			{
				Operator: overloadId3Args,
				Function: func(values ...ref.Val) ref.Val {
					name1 := values[0].(types.String).Value().(string)
					name2 := values[1].(types.String).Value().(string)

					if rm == nil {
						return types.Bool(name1 == name2)
					} else if len(values) == 2 {
						res, _ := rm.HasLink(name1, name2)
						return types.Bool(res)
					} else {
						domain := values[2].(types.String).Value().(string)
						res, _ := rm.HasLink(name1, name2, domain)
						return types.Bool(res)
					}
				}},
		}}
}
