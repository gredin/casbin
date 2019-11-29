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

package casbin

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/casbin/casbin/v2/util"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/interpreter/functions"
	"github.com/google/cel-go/parser"
	_ "github.com/mattn/go-sqlite3"
	"strconv"
	"strings"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	"github.com/casbin/casbin/v2/effect"
	"github.com/casbin/casbin/v2/log"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/casbin/casbin/v2/rbac"
	"github.com/casbin/casbin/v2/rbac/default-role-manager"
)

const (
	RuleTableName = "rule"
	SqliteMaxParameters = 999
)

// Enforcer is the main interface for authorization enforcement and policy management.
type Enforcer struct {
	modelPath string
	model     model.Model
	fm        model.FunctionMap
	eft       effect.Effector

	evaluator            cel.Program
	ruleConditionBuilder func(map[string]interface{}) (string, error)
	ruleDB               *sql.DB

	adapter persist.Adapter
	watcher persist.Watcher
	rm      rbac.RoleManager

	enabled            bool
	autoSave           bool
	autoBuildRoleLinks bool
}

// NewEnforcer creates an enforcer via file or DB.
//
// File:
//
// 	e := casbin.NewEnforcer("path/to/basic_model.conf", "path/to/basic_policy.csv")
//
// MySQL DB:
//
// 	a := mysqladapter.NewDBAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/")
// 	e := casbin.NewEnforcer("path/to/basic_model.conf", a)
//
func NewEnforcer(params ...interface{}) (*Enforcer, error) {
	e := &Enforcer{fm: model.LoadFunctionMap()}

	parsedParamLen := 0
	paramLen := len(params)
	if paramLen >= 1 {
		enableLog, ok := params[paramLen-1].(bool)
		if ok {
			e.EnableLog(enableLog)

			parsedParamLen++
		}
	}

	if paramLen-parsedParamLen == 2 {
		switch p0 := params[0].(type) {
		case string:
			switch p1 := params[1].(type) {
			case string:
				err := e.InitWithFile(p0, p1)
				if err != nil {
					return nil, err
				}
			default:
				err := e.InitWithAdapter(p0, p1.(persist.Adapter))
				if err != nil {
					return nil, err
				}
			}
		default:
			switch params[1].(type) {
			case string:
				return nil, errors.New("invalid parameters for enforcer")
			default:
				err := e.InitWithModelAndAdapter(p0.(model.Model), params[1].(persist.Adapter))
				if err != nil {
					return nil, err
				}
			}
		}
	} else if paramLen-parsedParamLen == 1 {
		switch p0 := params[0].(type) {
		case string:
			err := e.InitWithFile(p0, "")
			if err != nil {
				return nil, err
			}
		default:
			err := e.InitWithModelAndAdapter(p0.(model.Model), nil)
			if err != nil {
				return nil, err
			}
		}
	} else if paramLen-parsedParamLen == 0 {
		return e, nil
	} else {
		return nil, errors.New("invalid parameters for enforcer")
	}

	return e, nil
}

// InitWithFile initializes an enforcer with a model file and a policy file.
func (e *Enforcer) InitWithFile(modelPath string, policyPath string) error {
	a := fileadapter.NewAdapter(policyPath)
	return e.InitWithAdapter(modelPath, a)
}

// InitWithAdapter initializes an enforcer with a database adapter.
func (e *Enforcer) InitWithAdapter(modelPath string, adapter persist.Adapter) error {
	m, err := model.NewModelFromFile(modelPath)
	if err != nil {
		return err
	}

	err = e.InitWithModelAndAdapter(m, adapter)
	if err != nil {
		return err
	}

	e.modelPath = modelPath
	return nil
}

// InitWithModelAndAdapter initializes an enforcer with a model and a database adapter.
func (e *Enforcer) InitWithModelAndAdapter(m model.Model, adapter persist.Adapter) error {
	e.adapter = adapter

	err := e.SetModel(m)
	if err != nil {
		return err
	}

	// Do not initialize the full policy when using a filtered adapter
	fa, ok := e.adapter.(persist.FilteredAdapter)
	if e.adapter != nil && (!ok || ok && !fa.IsFiltered()) {
		err := e.LoadPolicy()
		if err != nil {
			return err
		}
	}

	return nil
}

func (e *Enforcer) initialize() error {
	e.rm = defaultrolemanager.NewRoleManager(10)
	e.eft = effect.NewDefaultEffector()
	e.watcher = nil
	e.evaluator = nil

	e.enabled = true
	e.autoSave = true
	e.autoBuildRoleLinks = true

	if e.ruleDB != nil {
		e.ruleDB.Close() // TODO handle error?
	}
	ruleDB, err := e.createDB()
	if err != nil {
		return err
	}
	e.ruleDB = ruleDB

	return err
}

func (e *Enforcer) initializeEvaluator() error {
	rawExpr := e.model["m"]["m"].Value // TODO might be empty "" - might be provided by EnforceWithMatcher(matcher string)

	parsedExpr, errs := parser.Parse(common.NewTextSource(rawExpr))
	if len(errs.GetErrors()) != 0 {
		return errors.New(errs.ToDisplayString())
	}

	flatExpr, identifiers, err := FlattenExpr(parsedExpr.GetExpr())
	if err != nil {
		return err
	}

	//expr2, err := PartiallyEvalExpr(flatExp)(flatObj)
	rawFlatExpr, err := parser.Unparse(flatExpr, parsedExpr.GetSourceInfo())
	if err != nil {
		return err
	}

	declarations, overloads, err := e.buildDeclarationsAndOverloads(identifiers)
	if err != nil {
		return err
	}

	env, err := cel.NewEnv(cel.Declarations(declarations...))
	if err != nil {
		return err
	}

	checkedAst, err := e.buildCheckedAst(rawFlatExpr, env)
	if err != nil {
		return err
	}

	program, err := env.Program(checkedAst, cel.Functions(overloads...))
	if err != nil {
		return err
	}
	e.evaluator = program

	e.ruleConditionBuilder = func(flatRequest map[string]interface{}) (string, error) {
		expr, err := PartiallyEvalExpr(flatExpr)(flatRequest)
		if err != nil {
			return "", err
		}

		return ExprToSQL(expr)

		// TODO return "1=1" if condition is empty
	}

	return nil
}

// LoadModel reloads the model from the model CONF file.
// Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
func (e *Enforcer) LoadModel() error {
	model, err := model.NewModelFromFile(e.modelPath)
	if err != nil {
		return err
	}

	err = e.SetModel(model)
	if err != nil {
		return err
	}

	return nil
}

// GetModel gets the current model.
func (e *Enforcer) GetModel() model.Model {
	return e.model
}

// SetModel sets the current model.
func (e *Enforcer) SetModel(m model.Model) error {
	e.model = m
	e.model.PrintModel()

	return e.initialize()
}

// GetAdapter gets the current adapter.
func (e *Enforcer) GetAdapter() persist.Adapter {
	return e.adapter
}

// SetAdapter sets the current adapter.
func (e *Enforcer) SetAdapter(adapter persist.Adapter) {
	e.adapter = adapter
}

// SetWatcher sets the current watcher.
func (e *Enforcer) SetWatcher(watcher persist.Watcher) error {
	e.watcher = watcher
	return watcher.SetUpdateCallback(func(string) { e.LoadPolicy() })
}

// GetRoleManager gets the current role manager.
func (e *Enforcer) GetRoleManager() rbac.RoleManager {
	return e.rm
}

// SetRoleManager sets the current role manager.
func (e *Enforcer) SetRoleManager(rm rbac.RoleManager) {
	e.rm = rm
}

// SetEffector sets the current effector.
func (e *Enforcer) SetEffector(eft effect.Effector) {
	e.eft = eft
}

// ClearPolicy clears all policy.
func (e *Enforcer) ClearPolicy() {
	e.model.ClearPolicy()
}

// LoadPolicy reloads the policy from file/database.
func (e *Enforcer) LoadPolicy() error {
	e.model.ClearPolicy()
	if err := e.adapter.LoadPolicy(e.model); err != nil && err.Error() != "invalid file path, file path cannot be empty" {
		return err
	}

	e.model.PrintPolicy()
	if e.autoBuildRoleLinks {
		err := e.BuildRoleLinks()
		if err != nil {
			return err
		}
	}

	err := e.updateDB()
	if err != nil {
		return err
	}

	return nil
}

// LoadFilteredPolicy reloads a filtered policy from file/database.
func (e *Enforcer) LoadFilteredPolicy(filter interface{}) error {
	e.model.ClearPolicy()

	var filteredAdapter persist.FilteredAdapter

	// Attempt to cast the Adapter as a FilteredAdapter
	switch adapter := e.adapter.(type) {
	case persist.FilteredAdapter:
		filteredAdapter = adapter
	default:
		return errors.New("filtered policies are not supported by this adapter")
	}
	if err := filteredAdapter.LoadFilteredPolicy(e.model, filter); err != nil && err.Error() != "invalid file path, file path cannot be empty" {
		return err
	}

	e.model.PrintPolicy()
	if e.autoBuildRoleLinks {
		err := e.BuildRoleLinks()
		if err != nil {
			return err
		}
	}
	return nil
}

// IsFiltered returns true if the loaded policy has been filtered.
func (e *Enforcer) IsFiltered() bool {
	filteredAdapter, ok := e.adapter.(persist.FilteredAdapter)
	if !ok {
		return false
	}
	return filteredAdapter.IsFiltered()
}

// SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
func (e *Enforcer) SavePolicy() error {
	if e.IsFiltered() {
		return errors.New("cannot save a filtered policy")
	}
	if err := e.adapter.SavePolicy(e.model); err != nil {
		return err
	}
	if e.watcher != nil {
		return e.watcher.Update()
	}
	return nil
}

// EnableEnforce changes the enforcing state of Casbin, when Casbin is disabled, all access will be allowed by the Enforce() function.
func (e *Enforcer) EnableEnforce(enable bool) {
	e.enabled = enable
}

// EnableLog changes whether Casbin will log messages to the Logger.
func (e *Enforcer) EnableLog(enable bool) {
	log.GetLogger().EnableLog(enable)
}

// EnableAutoSave controls whether to save a policy rule automatically to the adapter when it is added or removed.
func (e *Enforcer) EnableAutoSave(autoSave bool) {
	e.autoSave = autoSave
}

// EnableAutoBuildRoleLinks controls whether to rebuild the role inheritance relations when a role is added or deleted.
func (e *Enforcer) EnableAutoBuildRoleLinks(autoBuildRoleLinks bool) {
	e.autoBuildRoleLinks = autoBuildRoleLinks
}

// BuildRoleLinks manually rebuild the role inheritance relations.
func (e *Enforcer) BuildRoleLinks() error {
	err := e.rm.Clear()
	if err != nil {
		return err
	}

	err = e.model.BuildRoleLinks(e.rm)
	if err != nil {
		return err
	}

	e.evaluator = nil // TODO necessary for reinit overloads

	return err
}

// enforce use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
func (e *Enforcer) enforce(matcher string, rvals ...interface{}) (bool, error) {
	if !e.enabled {
		return true, nil
	}

	if e.evaluator == nil {
		err := e.initializeEvaluator()
		if err != nil {
			return false, err
		}
	}

	if len(rvals) != len(e.model["r"]["r"].Tokens) {
		return false, fmt.Errorf(
			"invalid request size: expected %d, got %d, rvals: %v",
			len(e.model["r"]["r"].Tokens),
			len(rvals),
			rvals)
	}

	request := map[string]interface{}{}
	for j, rval := range rvals {
		token := e.model["r"]["r"].Tokens[j]
		request[token] = rval
	}

	flatRequest, err := Flatten(request, "", FuncMerger(func(top bool, key, subkey string) string {
		if top {
			key += subkey // TODO pas besoin de ReplaceDots car request = { r_sub => ..., r_obj => ... }
		} else {
			key += "_" + util.ReplaceDots(subkey)
		}

		return key
	}))
	if err != nil {
		// TODO
	}

	// TODO 2 cases: matcher = "" AND matcher != ""
	/*
	var expString string
	if matcher == "" {
		expString = e.model["m"]["m"].Value
	} else {
		expString = matcher
	}
	expression, err := govaluate.NewEvaluableExpressionWithFunctions(expString, funcs)
	if err != nil {
		return false, err
	}
	*/
	pTokens := e.model["p"]["p"].Tokens
	pTokensLen := len(pTokens)
	var policyEffects []effect.Effect
	var matcherResults []float64
	if policyLen := e.model["p"]["p"].Policy.Len(); policyLen != 0 {
		sqlCondition, err := e.ruleConditionBuilder(flatRequest)
		if err != nil {
			// TODO
		}

		ruleIds := []int{}
		rows, err := e.ruleDB.Query(
			fmt.Sprintf("SELECT id FROM %s WHERE %s", RuleTableName, sqlCondition))
		if err != nil {
			// TODO
		}
		defer rows.Close()
		for rows.Next() {
			var id int
			err = rows.Scan(&id)
			if err != nil {
				// TODO
			}

			ruleIds = append(ruleIds, id)
		}
		err = rows.Err()
		if err != nil {
			// TODO
		}

		policyEffects = make([]effect.Effect, len(ruleIds)+1)
		matcherResults = make([]float64, len(ruleIds)+1)
		policyEffects[len(ruleIds)] = effect.Indeterminate // TODO explain why

		effectTokenIndex := -1
		for j, token := range pTokens {
			if token == "p_eft" {
				effectTokenIndex = j
				break
			}
		}

		vars := flatRequest

		for i, ruleId := range ruleIds {
			pvals, ok := e.model["p"]["p"].Policy.Get(ruleId)
			if !ok {
				// TODO ??!! (consistency issue between DB and model["p"]["p"].Policy)
			}

			// log.LogPrint("Policy Rule: ", pvals)
			if len(pvals) != pTokensLen {
				return false, fmt.Errorf(
					"invalid policy size: expected %d, got %d, pvals: %v",
					pTokensLen,
					len(pvals),
					pvals)
			}

			for j, pval := range pvals {
				token := pTokens[j]
				vars[token] = pval
			}

			result, _, err := e.evaluator.Eval(vars)

			/*
			parameters.pVals = pvals

			result, err := expression.Eval(parameters)
			// log.LogPrint("Result: ", result)
			*/

			if err != nil {
				return false, err
			}

			switch result.Type() {
			case types.BoolType:
				resultVal := result.Value().(bool)

				if !resultVal {
					policyEffects[i] = effect.Indeterminate
					continue
				}
			case types.IntType:
				resultVal := result.Value().(int64) // see github.com/google/cel-go@v0.3.2/common/types/int.go

				if resultVal == 0 {
					policyEffects[i] = effect.Indeterminate
					continue
				} else {
					matcherResults[i] = float64(resultVal)
				}
			case types.DoubleType:
				resultVal := result.Value().(float64) // see github.com/google/cel-go@v0.3.2/common/types/double.go

				if resultVal == 0 {
					policyEffects[i] = effect.Indeterminate
					continue
				} else {
					matcherResults[i] = resultVal
				}
			default:
				return false, errors.New("matcher result should be bool, int or float")
			}

			if effectTokenIndex >= 0 {
				eft := pvals[effectTokenIndex]
				if eft == "allow" {
					policyEffects[i] = effect.Allow
				} else if eft == "deny" {
					policyEffects[i] = effect.Deny
				} else {
					policyEffects[i] = effect.Indeterminate
				}
			} else {
				policyEffects[i] = effect.Allow
			}

			if e.model["e"]["e"].Value == effect.Priority {
				break
			}
		}
	} else {
		policyEffects = make([]effect.Effect, 1)
		matcherResults = make([]float64, 1)

		/*
		parameters.pVals = make([]string, len(parameters.pTokens))

		result, err := expression.Eval(parameters)
		// log.LogPrint("Result: ", result)
		*/

		// TODO code duplication
		vars := flatRequest
		for _, token := range pTokens {
			vars[token] = ""
		}

		result, _, err := e.evaluator.Eval(vars)

		if err != nil {
			return false, err
		}

		// TODO
		a, ok := result.Value().(bool)
		_ = a
		if ok {
			policyEffects[0] = effect.Allow
		} else {
			policyEffects[0] = effect.Indeterminate
		}
	}

	// log.LogPrint("Rule Results: ", policyEffects)

	result, err := e.eft.MergeEffects(e.model["e"]["e"].Value, policyEffects, matcherResults)
	if err != nil {
		return false, err
	}

	// Log request.
	if log.GetLogger().IsEnabled() {
		var reqStr strings.Builder
		reqStr.WriteString("Request: ")
		for i, rval := range rvals {
			if i != len(rvals)-1 {
				reqStr.WriteString(fmt.Sprintf("%v, ", rval))
			} else {
				reqStr.WriteString(fmt.Sprintf("%v", rval))
			}
		}
		reqStr.WriteString(fmt.Sprintf(" ---> %t", result))
		log.LogPrint(reqStr.String())
	}

	return result, nil
}

// Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
func (e *Enforcer) Enforce(rvals ...interface{}) (bool, error) {
	return e.enforce("", rvals...)
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
func (e *Enforcer) EnforceWithMatcher(matcher string, rvals ...interface{}) (bool, error) {
	// TODO handle this case (ruleDB not used)

	return e.enforce(matcher, rvals...)
}

func (e *Enforcer) createDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, err
	}
	//defer db.Close()

	sqlColumns := []string{"id INTEGER NOT NULL PRIMARY KEY"}
	sqlIndexes := []string{}

	countTokens := len(e.model["p"]["p"].Tokens)
	fields := make([]string, countTokens+1)
	fields[0] = "id"
	questionMarks := make([]string, countTokens+1)
	questionMarks[0] = "?"

	for i, token := range e.model["p"]["p"].Tokens {
		sqlColumns = append(sqlColumns, fmt.Sprintf("%s TEXT", token))
		sqlIndexes = append(sqlIndexes, fmt.Sprintf("CREATE INDEX %s_index ON %s (%s)", token, RuleTableName, token))

		fields[i+1] = token
		questionMarks[i+1] = "?"
	}

	sqlStmt := fmt.Sprintf("BEGIN; CREATE TABLE %s (%s); %s; COMMIT;",
		RuleTableName,
		strings.Join(sqlColumns, ","),
		strings.Join(sqlIndexes, ";"))

	_, err = db.Exec(sqlStmt)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func (e *Enforcer) updateDB() error {
	countTokens := len(e.model["p"]["p"].Tokens)
	// frequent inserts in order to avoid "too many SQL variables" (default SQLITE_MAX_VARIABLE_NUMBER = 999)
	batchSize := int(SqliteMaxParameters / (countTokens + 1))

	// TODO code duplication
	fields := make([]string, countTokens+1)
	fields[0] = "id"
	questionMarks := make([]string, countTokens+1)
	questionMarks[0] = "?"
	for i, token := range e.model["p"]["p"].Tokens {
		fields[i+1] = token
		questionMarks[i+1] = "?"
	}

	valuesStatements := []string{}
	values := []interface{}{}

	policy := e.model["p"]["p"].Policy
	policyLen := e.model["p"]["p"].Policy.Len()
	sqlVariableNumber := 1
	sqlVariables := make([]string, countTokens+1)

	i := 0
	for policy.Begin(); policy.Next(); {
		ruleId, rule := policy.GetNext()

		for j := 0; j < countTokens+1; j++ {
			sqlVariables[j] = "$" + strconv.Itoa(sqlVariableNumber)
			sqlVariableNumber++
		}
		valuesStatements = append(valuesStatements, "("+strings.Join(sqlVariables, ",")+")")

		values = append(values, ruleId)
		for _, v := range rule {
			values = append(values, v)
		}

		if (i%batchSize == 0 && i != 0) || i == policyLen-1 {
			query := fmt.Sprintf("INSERT INTO %s (%s) VALUES ", RuleTableName, strings.Join(fields, ",")) +
				strings.Join(valuesStatements, ",")

			if _, err := e.ruleDB.Exec(query, values...); err != nil {
				return err
			}

			valuesStatements = []string{}
			values = []interface{}{}
		}

		i++
	}

	return nil
}

func (e *Enforcer) addRuleToDB(ruleId int, rule []string) error {
	countTokens := len(e.model["p"]["p"].Tokens)
	// TODO code duplication
	fields := make([]string, countTokens+1)
	fields[0] = "id"
	questionMarks := make([]string, countTokens+1)
	questionMarks[0] = "?"
	for i, token := range e.model["p"]["p"].Tokens {
		fields[i+1] = token
		questionMarks[i+1] = "?"
	}

	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		RuleTableName, strings.Join(fields, ","), strings.Join(questionMarks, ","))

	// TODO make sure len(rule) == len(tokens)
	values := make([]interface{}, len(rule)+1)
	values[0] = ruleId
	for i, v := range rule {
		values[i+1] = v
	}

	if _, err := e.ruleDB.Exec(query, values...); err != nil {
		return err
	}

	return nil
}

func (e *Enforcer) deleteRulesFromDB(ruleIds []int) error {
	countRules := len(ruleIds)

	questionMarks := []string{}
	values := []interface{}{}

	for i, ruleId := range ruleIds {
		questionMarks = append(questionMarks, "?")
		values = append(values, ruleId)

		if (i%SqliteMaxParameters == 0 && i != 0) || i == countRules-1 {
			query := fmt.Sprintf("DELETE FROM %s WHERE id IN (%s)", RuleTableName, strings.Join(questionMarks, ","))

			if _, err := e.ruleDB.Exec(query, values...); err != nil {
				return err
			}

			questionMarks = []string{}
			values = []interface{}{}
		}
	}

	return nil
}

func (e *Enforcer) deleteRuleFromDB(rule []string) error {
	// TODO make sure len(rule) = len(token)

	countTokens := len(e.model["p"]["p"].Tokens)

	conditions := make([]string, countTokens)
	values := make([]interface{}, countTokens)

	for i, token := range e.model["p"]["p"].Tokens {
		conditions[i] = token + " = ?"
		values[i] = rule[i]
	}

	// TODO make sure conditions is not empty (=> sql syntax error)
	query := fmt.Sprintf("DELETE FROM %s WHERE %s", RuleTableName, strings.Join(conditions, " AND "))

	if _, err := e.ruleDB.Exec(query, values...); err != nil {
		return err
	}

	return nil
}

func (e *Enforcer) buildDeclarationsAndOverloads(identifiers []string) ([]*exprpb.Decl, []*functions.Overload, error) {
	declarations := []*exprpb.Decl{}
	for _, identifier := range identifiers {
		declarations = append(declarations, decls.NewIdent(identifier, decls.Any, nil))
	}
	/*
	for _, t := range e.model["r"]["r"].Tokens {
		declarations = append(declarations, decls.NewIdent(t, decls.Any, nil))
	}
	for _, t := range e.model["p"]["p"].Tokens {
		declarations = append(declarations, decls.NewIdent(t, decls.Any, nil))
	}
	*/

	overloads := []*functions.Overload{}
	for _, f := range e.fm {
		declarations = append(declarations, f.Declaration)

		for _, overload := range f.Overloads {
			overloads = append(overloads, overload)
		}
	}

	if _, ok := e.model["g"]; ok {
		for key, ast := range e.model["g"] {
			f := model.GenerateGFunction(key, ast.RM)

			declarations = append(declarations, f.Declaration)

			for _, overload := range f.Overloads {
				overloads = append(overloads, overload)
			}
		}
	}

	return declarations, overloads, nil
	//return cel.NewEnv(cel.Declarations(declarations...))
}

func (e *Enforcer) buildCheckedAst(rawExpr string, env cel.Env) (cel.Ast, error) {
	parsed, issues := env.Parse(rawExpr)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}

	checked, issues := env.Check(parsed)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}

	return checked, nil
}
