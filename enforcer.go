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
	"github.com/google/cel-go/common/types/ref"
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
	TableName = "policy"
)

// Enforcer is the main interface for authorization enforcement and policy management.
type Enforcer struct {
	modelPath string
	model     model.Model
	fm        model.FunctionMap
	eft       effect.Effector

	evaluator           cel.Program
	sqlConditionBuilder func(map[string]interface{}) (string, error)
	sqliteDB            *sql.DB
	//db                  *memdb.MemDB

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

	/*
	db, err := e.buildDB()
	if err != nil {
		return nil, err
	}
	e.db = db
	*/

	/*
	checkedAst, err := e.buildCheckedAst(rawExpr, env)
	if err != nil {
		// TODO
	}

	checkedExpr := checkedAst.Expr()

	flattenExpr, err := FlattenExpr(checkedExpr)
	if err != nil {
		// TODO
	}

	rawFlattenExpr, err := cel.AstToString()
	if err != nil {
		// TODO
	}

	flattenAst, err := e.buildCheckedAst(rawFlattenExpr, env)
	if err != nil {
		// TODO
	}
	*/

	/*
	evaluator, err := e.BuildEvaluator()
	if err != nil {
		return nil, err
	}
	e.evaluator = evaluator



	// "SQL query engine"
	// sqlite in memory
	// AST => sql query

	txn := db.Txn(false)
	defer txn.Abort()
	it, err := txn.Get("policy", "p_sub", "corp:Chanel")
	if err != nil {
		// TODO
	}

	fmt.Println("***")
	for obj := it.Next(); obj != nil; obj = it.Next() {
		reader := dynamicstruct.NewReader(obj)
		println(reader.GetField("Id").Int())
	}
	fmt.Println("***")
	*/

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

	e.enabled = true
	e.autoSave = true
	e.autoBuildRoleLinks = true

	if e.sqliteDB != nil {
		e.sqliteDB.Close() // TODO handle error?
	}
	sqliteDB, err := e.createDB()
	if err != nil {
		return err
	}
	e.sqliteDB = sqliteDB

	declarations, overloads, err := e.buildDeclarationsAndOverloads()
	if err != nil {
		return err
	}

	env, err := cel.NewEnv(cel.Declarations(declarations...))
	if err != nil {
		return err
	}

	rawExpr := e.model["m"]["m"].Value // TODO might be provided by EnforceWithMatcher(matcher string)

	parsedExpr, errs := parser.Parse(common.NewTextSource(rawExpr))
	if len(errs.GetErrors()) != 0 {
		return errors.New(errs.ToDisplayString())
	}

	flatExpr, err := FlattenExpr(parsedExpr.GetExpr())
	if err != nil {
		return err
	}

	//expr2, err := PartiallyEvalExpr(flatExp)(flatObj)
	rawFlatExpr, err := parser.Unparse(flatExpr, parsedExpr.GetSourceInfo())
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

	e.sqlConditionBuilder = func(flatRequest map[string]interface{}) (string, error) {
		expr, err := PartiallyEvalExpr(flatExpr)(flatRequest)
		if err != nil {
			return "", err
		}

		return ExprToSQL(expr)
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

	return e.model.BuildRoleLinks(e.rm)
}

// enforce use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
func (e *Enforcer) enforce(matcher string, rvals ...interface{}) (bool, error) {
	if !e.enabled {
		return true, nil
	}

	/*
	funcs := model.FunctionMap{}
	for k, v := range e.fm {
		funcs[k] = v
	}
	if _, ok := e.model["g"]; ok {
		for key, ast := range e.model["g"] {
			rm := ast.RM
			funcs[key] = util.GenerateGFunction(rm)
		}
	}
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

	rTokens := make(map[string]int, len(e.model["r"]["r"].Tokens))
	for i, token := range e.model["r"]["r"].Tokens {
		rTokens[token] = i
	}
	pTokens := make(map[string]int, len(e.model["p"]["p"].Tokens))
	for i, token := range e.model["p"]["p"].Tokens {
		pTokens[token] = i
	}

	parameters := enforceParameters{
		rTokens: rTokens,
		rVals:   rvals,

		pTokens: pTokens,
	}
	*/

	request := map[string]interface{}{}
	for j, rval := range rvals {
		token := e.model["r"]["r"].Tokens[j]
		request[token] = rval
	}

	flatRequest, err := Flatten(request, "", FuncMerger(func(top bool, key, subkey string) string {
		if top {
			key += subkey // TODO pas besoin de EscapeDots car request = { r_sub => ..., r_obj => ... }
		} else {
			key += "_" + util.EscapeDots(subkey)
		}

		return key
	}))
	if err != nil {
		// TODO
	}

	sqlCondition, err := e.sqlConditionBuilder(flatRequest)
	if err != nil {
		// TODO
	}

	policyIds := []int{}
	rows, err := e.sqliteDB.Query("SELECT id FROM policy WHERE " + sqlCondition)
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

		policyIds = append(policyIds, id)
	}
	err = rows.Err()
	if err != nil {
		// TODO
	}

	var policyEffects []effect.Effect
	var matcherResults []float64
	if policyLen := len(e.model["p"]["p"].Policy); policyLen != 0 {
		policyEffects = make([]effect.Effect, len(policyIds)+1)
		matcherResults = make([]float64, len(policyIds)+1)
		policyEffects[len(policyIds)] = effect.Indeterminate // TODO explain why

		if len(e.model["r"]["r"].Tokens) != len(rvals) {
			return false, fmt.Errorf(
				"invalid request size: expected %d, got %d, rvals: %v",
				len(e.model["r"]["r"].Tokens),
				len(rvals),
				rvals)
		}

		effectTokenIndex := -1
		for j, token := range e.model["p"]["p"].Tokens {
			if token == "p_eft" {
				effectTokenIndex = j
				break
			}
		}

		vars := map[string]interface{}{}
		for j, rval := range rvals {
			token := e.model["r"]["r"].Tokens[j]
			vars[token] = rval
		}

		for i, policyId := range policyIds {
			pvals := e.model["p"]["p"].Policy[policyId]

			// log.LogPrint("Policy Rule: ", pvals)
			if len(e.model["p"]["p"].Tokens) != len(pvals) {
				return false, fmt.Errorf(
					"invalid policy size: expected %d, got %d, pvals: %v",
					len(e.model["p"]["p"].Tokens),
					len(pvals),
					pvals)
			}

			for j, pval := range pvals {
				token := e.model["p"]["p"].Tokens[j]
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
		vars := map[string]interface{}{}
		for j, rval := range rvals {
			token := e.model["r"]["r"].Tokens[j]
			vars[token] = rval
		}

		result, _, err := e.evaluator.Eval(vars)

		if err != nil {
			return false, err
		}

		if result.Value().(bool) {
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
	// TODO handle this case (sqliteDB not used)

	return e.enforce(matcher, rvals...)
}

// TODO not used anymore
// assumes bounds have already been checked
type enforceParameters struct {
	rTokens map[string]int
	rVals   []interface{}

	pTokens map[string]int
	pVals   []string
}

// TODO not used anymore
// implements govaluate.Parameters
func (p enforceParameters) Get(name string) (interface{}, error) {
	if name == "" {
		return nil, nil
	}

	switch name[0] {
	case 'p':
		i, ok := p.pTokens[name]
		if !ok {
			return nil, errors.New("No parameter '" + name + "' found.")
		}
		return p.pVals[i], nil
	case 'r':
		i, ok := p.rTokens[name]
		if !ok {
			return nil, errors.New("No parameter '" + name + "' found.")
		}
		return p.rVals[i], nil
	default:
		return nil, errors.New("No parameter '" + name + "' found.")
	}
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
		sqlIndexes = append(sqlIndexes, fmt.Sprintf("CREATE INDEX %s_index ON %s (%s)", token, TableName, token))

		fields[i+1] = token
		questionMarks[i+1] = "?"
	}

	sqlStmt := fmt.Sprintf("BEGIN; CREATE TABLE %s (%s); %s; COMMIT;",
		TableName,
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
	batchSize := int(999 / (countTokens + 1))

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

	countPolicies := e.model["p"]["p"].Policy
	sqlVariableNumber := 1
	sqlVariables := make([]string, countTokens+1)
	for i, policy := range e.model["p"]["p"].Policy {
		for j := 0; j < countTokens+1; j++ {
			sqlVariables[j] = "$" + strconv.Itoa(sqlVariableNumber)
			sqlVariableNumber++
		}
		valuesStatements = append(valuesStatements, "("+strings.Join(sqlVariables, ",")+")")

		values = append(values, i)
		for _, v := range policy {
			values = append(values, v)
		}

		if (i%batchSize == 0 && i != 0) || i == len(countPolicies)-1 {
			query := fmt.Sprintf("INSERT INTO %s (%s) VALUES ", TableName, strings.Join(fields, ",")) +
				strings.Join(valuesStatements, ",")

			if _, err := e.sqliteDB.Exec(query, values...); err != nil {
				return err
			}

			valuesStatements = []string{}
			values = []interface{}{}
		}
	}

	return nil

	/*
	rows, err := db.Query("select id from policy")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		err = rows.Scan(&id)
		if err != nil {
			return nil, err
		}
		fmt.Println("=>", id)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}
	*/
}

// TODO PROBLÈME : quand on va supprimer des policies de l'array, ça va fausser la correspondance entre index en db et index dans l'array !!!
func (e *Enforcer) addPolicyToDB(rule []string) error {
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
		TableName, strings.Join(fields, ","), strings.Join(questionMarks, ","))

	// TODO make sure len(rule) == len(tokens)
	values := make([]interface{}, len(rule)+1)
	values[0] = len(e.model["p"]["p"].Policy) - 1 // TODO is that enough to ensure policy index in db table is identical to its index in policy array?
	for i, v := range rule {
		values[i+1] = v
	}

	if _, err := e.sqliteDB.Exec(query, values...); err != nil {
		return err
	}

	return nil
}

/*
func (e *Enforcer) buildDB() (*memdb.MemDB, error) {
	indexes := map[string]*memdb.IndexSchema{}
	indexes["id"] = &memdb.IndexSchema{
		Name:    "id",
		Unique:  true,
		Indexer: &memdb.IntFieldIndex{Field: "Id"},
	}
	for _, token := range e.model["p"]["p"].Tokens {
		indexes[token] = &memdb.IndexSchema{
			Name:    token,
			Unique:  false,
			Indexer: &memdb.StringFieldIndex{Field: strings.Title(token)},
		}
	}

	schema := &memdb.DBSchema{
		Tables: map[string]*memdb.TableSchema{
			"policy": &memdb.TableSchema{
				Name:    "policy",
				Indexes: indexes,
			},
		},
	}

	db, err := memdb.NewMemDB(schema)
	if err != nil {
		return nil, err
	}

	txn := db.Txn(true)

	builder := dynamicstruct.NewStruct()
	builder = builder.AddField("Id", 0, `json:"id"`)
	for _, token := range e.model["p"]["p"].Tokens {
		builder = builder.AddField(strings.Title(token), "", fmt.Sprintf(`json:"%s"`, token))
	}

	for i, policy := range e.model["p"]["p"].Policy {
		p := map[string]interface{}{"id": i}
		for j, token := range e.model["p"]["p"].Tokens {
			p[token] = policy[j] // check p and policy have same length
		}

		data, err := json.Marshal(p)
		if err != nil {
			println(err.Error())
		}

		instance := builder.Build().New()
		err = json.Unmarshal(data, &instance)
		if err != nil {
			println(err.Error())
		}

		err = txn.Insert("policy", instance)
		if err != nil {
			println(err.Error())
		}
	}

	txn.Commit()

	return db, nil
}
*/

func (e *Enforcer) buildDeclarationsAndOverloads() ([]*exprpb.Decl, []*functions.Overload, error) {
	declarations := []*exprpb.Decl{}
	for _, t := range e.model["r"]["r"].Tokens {
		declarations = append(declarations, decls.NewIdent(t, decls.Any, nil))
	}
	for _, t := range e.model["p"]["p"].Tokens {
		declarations = append(declarations, decls.NewIdent(t, decls.Any, nil))
	}

	overloads := []*functions.Overload{}
	for _, f := range e.fm {
		declarations = append(declarations, f.Declaration)
		overloads = append(overloads, f.Overload)
	}

	if _, ok := e.model["g"]; ok {
		for key, ast := range e.model["g"] {
			rm := ast.RM

			overloadId2Args := fmt.Sprintf("%s_string_string", key)
			overloadId3Args := fmt.Sprintf("%s_string_string_string", key)

			declarations = append(declarations,
				decls.NewFunction(key,
					decls.NewOverload(overloadId2Args,
						[]*exprpb.Type{decls.String, decls.String}, decls.Bool),
					decls.NewOverload(overloadId3Args,
						[]*exprpb.Type{decls.String, decls.String, decls.String}, decls.Bool)))

			overloads = append(overloads, &functions.Overload{
				Operator: overloadId2Args,
				Binary: func(val1 ref.Val, val2 ref.Val) ref.Val {
					name1 := val1.(types.String).Value().(string)
					name2 := val2.(types.String).Value().(string)

					if rm == nil {
						return types.Bool(name1 == name2)
					}

					res, _ := rm.HasLink(name1, name2)

					return types.Bool(res)
				}})
			overloads = append(overloads, &functions.Overload{
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
				}})
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
