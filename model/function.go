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
	"github.com/casbin/casbin/v2/util"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

type Function struct {
	Declaration *exprpb.Decl
	Overload    *functions.Overload
}

// FunctionMap represents the collection of Function.
type FunctionMap map[string]Function

// TODO should be private because all funcs should provided at instantiation of Enforcer
// AddFunction adds an expression function.
func (fm FunctionMap) AddFunction(function Function) {
	fm[function.Declaration.Name] = function
}

// LoadFunctionMap loads an initial function map.
func LoadFunctionMap() FunctionMap {
	fm := make(FunctionMap)

	fm.AddFunction(Function{
		Declaration: decls.NewFunction("keyMatch",
			decls.NewOverload("keyMatch_string_string",
				[]*exprpb.Type{decls.String, decls.String}, decls.Bool)),
		Overload: &functions.Overload{
			Operator: "keyMatch_string_string",
			Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
				val1 := lhs.(types.String).Value().(string)
				val2 := rhs.(types.String).Value().(string)

				return types.Bool(util.KeyMatch(val1, val2))
			}},
	})

	fm.AddFunction(Function{
		Declaration: decls.NewFunction("keyMatch2",
			decls.NewOverload("keyMatch2_string_string",
				[]*exprpb.Type{decls.String, decls.String}, decls.Bool)),
		Overload: &functions.Overload{
			Operator: "keyMatch2_string_string",
			Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
				val1 := lhs.(types.String).Value().(string)
				val2 := rhs.(types.String).Value().(string)

				return types.Bool(util.KeyMatch2(val1, val2))
			}},
	})

	fm.AddFunction(Function{
		Declaration: decls.NewFunction("keyMatch3",
			decls.NewOverload("keyMatch3_string_string",
				[]*exprpb.Type{decls.String, decls.String}, decls.Bool)),
		Overload: &functions.Overload{
			Operator: "keyMatch3_string_string",
			Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
				val1 := lhs.(types.String).Value().(string)
				val2 := rhs.(types.String).Value().(string)

				return types.Bool(util.KeyMatch3(val1, val2))
			}},
	})

	fm.AddFunction(Function{
		Declaration: decls.NewFunction("keyMatch4",
			decls.NewOverload("keyMatch4_string_string",
				[]*exprpb.Type{decls.String, decls.String}, decls.Bool)),
		Overload: &functions.Overload{
			Operator: "keyMatch4_string_string",
			Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
				val1 := lhs.(types.String).Value().(string)
				val2 := rhs.(types.String).Value().(string)

				return types.Bool(util.KeyMatch4(val1, val2))
			}},
	})

	fm.AddFunction(Function{
		Declaration: decls.NewFunction("regexMatch",
			decls.NewOverload("regexMatch_string_string",
				[]*exprpb.Type{decls.String, decls.String}, decls.Bool)),
		Overload: &functions.Overload{
			Operator: "regexMatch_string_string",
			Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
				val1 := lhs.(types.String).Value().(string)
				val2 := rhs.(types.String).Value().(string)

				return types.Bool(util.RegexMatch(val1, val2))
			}},
	})

	fm.AddFunction(Function{
		Declaration: decls.NewFunction("ipMatch",
			decls.NewOverload("ipMatch_string_string",
				[]*exprpb.Type{decls.String, decls.String}, decls.Bool)),
		Overload: &functions.Overload{
			Operator: "ipMatch_string_string",
			Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
				val1 := lhs.(types.String).Value().(string)
				val2 := rhs.(types.String).Value().(string)

				return types.Bool(util.IPMatch(val1, val2))
			}},
	})

	return fm
}
