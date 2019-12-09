package model

import (
	"database/sql"
	"fmt"
	"github.com/casbin/casbin/v2/rbac"
	"strconv"
	"strings"
	_ "github.com/mattn/go-sqlite3"
)

/* TODO initialize
p, ok := e.model.GetAssertion("p", "p")
if ok && p.Policy != nil && p.Policy.Len() > 0 { // TODO explain it is useful for SetModel(...)
	err = e.updateDB()

	return err
}
*/

/*
func (e *Enforcer) LoadPolicy() error {
=> err := e.updateDB()
 */

const (
	RuleTableName       = "rule"
	SqliteMaxParameters = 999
)

type ModelDB struct {
	// TODO name "modeldb"
	assertionModel AssertionModel
	ruleDB         *sql.DB
}

func NewModelDBFromFile(path string) (*ModelDB, error) { // TODO name "modeldb"
	assertionModel, err := NewAssertionModelFromFile(path)
	if err != nil {
		return nil, err
	}

	model := ModelDB{assertionModel: assertionModel}

	err = model.initializeRuleDB()
	if err != nil {
		return nil, err
	}

	return &model, nil
}

func (model *ModelDB) GetAssertionMap(key string) (AssertionMap, bool) {
	return model.assertionModel.GetAssertionMap(key)
}

func (model *ModelDB) GetAssertion(sec string, key string) (*Assertion, bool) {
	return model.assertionModel.GetAssertion(sec, key)
}

func (model *ModelDB) AddDef(sec string, key string, value string) bool {
	result := model.assertionModel.AddDef(sec, key, value)

	if sec == "p" { // TODO  && key == "p" (only one "p" supported for now)
		err := model.initializeRuleDB()
		if err != nil {
			// TODO
		}
	}

	return result
}

func (model *ModelDB) AddPolicy(sec string, ptype string, rule []string) (bool, int) {
	if sec == "p" { // TODO? && ptype == "p"
		return model.addPolicyRule(sec, ptype, rule)
	}

	return model.assertionModel.AddPolicy(sec, ptype, rule)
}

func (model *ModelDB) addPolicyRule(sec string, ptype string, rule []string) (bool, int) {
	if model.HasPolicy(sec, ptype, rule) {
		return false, 0
	}

	ruleId := model.assertionModel.addPolicyWithoutDuplicateCheck(sec, ptype, rule)

	// TODO db does not support "ptype"
	// TODO but "Currently only single policy definition p is supported. p2 is yet not supported." https://casbin.org/docs/en/syntax-for-models#policy-definition
	err := model.addRuleToDB(ruleId, rule)
	if err != nil {
		// TODO not good because adapter policy addition is not called
		return false, ruleId // TODO return false?
	}

	return true, ruleId
}

func (model *ModelDB) BuildRoleLinks(rm rbac.RoleManager) error {
	return model.assertionModel.BuildRoleLinks(rm)
}

func (model *ModelDB) ClearPolicy() {
	model.clearRuleDB() // TODO handle error
	model.assertionModel.ClearPolicy()
}

func (model *ModelDB) GetAllRules() PolicyIterator {
	assertionPolicy, _ := model.assertionModel.GetAssertion("p", "p")

	return NewCompleteIterator(assertionPolicy.Policy)
}

func (model *ModelDB) FindRules(sqlCondition string) (PolicyIterator, error) {
	sqlQuery := fmt.Sprintf("SELECT id FROM %s WHERE %s", RuleTableName, sqlCondition)

	rows, err := model.ruleDB.Query(sqlQuery)
	if err != nil {
		// TODO
	}
	defer rows.Close()

	ruleIds := []int{}
	var id int
	for rows.Next() {
		err = rows.Scan(&id)
		if err != nil {
			return nil, err
		}

		ruleIds = append(ruleIds, id)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}

	assertionPolicy, _ := model.assertionModel.GetAssertion("p", "p")

	return NewPartialIterator(&ruleIds, assertionPolicy.Policy), nil
}

func (model *ModelDB) GetFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) [][]string {
	return model.assertionModel.GetFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
}

func (model *ModelDB) GetPolicy(sec string, ptype string) [][]string {
	return model.assertionModel.GetPolicy(sec, ptype)
}

func (model *ModelDB) GetValuesForFieldInPolicy(sec string, ptype string, fieldIndex int) []string {
	return model.assertionModel.GetValuesForFieldInPolicy(sec, ptype, fieldIndex)
}

func (model *ModelDB) GetValuesForFieldInPolicyAllTypes(sec string, fieldIndex int) []string {
	return model.assertionModel.GetValuesForFieldInPolicyAllTypes(sec, fieldIndex)
}

func (model *ModelDB) HasPolicy(sec string, ptype string, rule []string) bool {
	if sec == "p" { // TODO? && ptype == "p"
		return model.hasPolicyRule(rule)
	}

	return model.assertionModel.HasPolicy(sec, ptype, rule)
}

func (model *ModelDB) hasPolicyRule(rule []string) bool {
	assertionPolicy, _ := model.assertionModel.GetAssertion("p", "p")

	countTokens := len(assertionPolicy.Tokens)
	conditions := make([]string, countTokens)
	values := make([]interface{}, countTokens)

	for i, token := range assertionPolicy.Tokens {
		conditions[i] = fmt.Sprintf("%s = ?", token)
		values[i] = rule[i]
	}

	sqlQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s",
		RuleTableName, strings.Join(conditions, " AND "))

	rows, err := model.ruleDB.Query(sqlQuery, values...)
	if err != nil {
		// TODO
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		err = rows.Scan(&count)
		if err != nil {
			// TODO
		}
	}
	err = rows.Err()
	if err != nil {
		// TODO
	}

	return count >= 1
}

func (model *ModelDB) LoadModel(path string) error {
	err := model.assertionModel.LoadModel(path)
	if err != nil {
		return err
	}

	return model.initializeRuleDB()
}

func (model *ModelDB) LoadModelFromText(text string) error {
	err := model.assertionModel.LoadModelFromText(text)
	if err != nil {
		return err
	}

	return model.initializeRuleDB()
}

func (model *ModelDB) PrintModel() {
	model.assertionModel.PrintModel()
}

func (model *ModelDB) PrintPolicy() {
	model.assertionModel.PrintPolicy()
}

func (model *ModelDB) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) (bool, []int) {
	ruleRemoved, ruleIds := model.assertionModel.RemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
	if !ruleRemoved {
		return ruleRemoved, []int{}
	}

	if sec == "p" {
		// TODO db does not support "ptype"
		// TODO but "Currently only single policy definition p is supported. p2 is yet not supported." https://casbin.org/docs/en/syntax-for-models#policy-definition
		err := model.deleteRulesFromDB(ruleIds)
		if err != nil {
			// TODO not good because adapter policy removal is not called
			return ruleRemoved, ruleIds // TODO ?
		}
	}

	return ruleRemoved, ruleIds
}

func (model *ModelDB) RemovePolicy(sec string, ptype string, rule []string) (bool, int) {
	ruleRemoved, ruleId := model.assertionModel.RemovePolicy(sec, ptype, rule)
	if !ruleRemoved {
		return ruleRemoved, -1 // TODO -1?
	}

	if sec == "p" {
		// TODO db does not support "ptype"
		// TODO but "Currently only single policy definition p is supported. p2 is yet not supported." https://casbin.org/docs/en/syntax-for-models#policy-definition
		err := model.deleteRulesFromDB([]int{ruleId})
		if err != nil {
			// TODO not good because adapter policy removal is not called
			return ruleRemoved, ruleId // TODO return false?
		}
	}

	return ruleRemoved, ruleId
}

func (model *ModelDB) initializeRuleDB() error {
	if model.ruleDB != nil {
		model.ruleDB.Close() // TODO handle error?
	}

	ruleDB, err := model.createRuleDB()
	if err != nil {
		return err
	}

	model.ruleDB = ruleDB

	return nil
}

func (model *ModelDB) createRuleDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, err
	}
	//defer db.Close()

	sqlColumns := []string{"id INTEGER NOT NULL PRIMARY KEY"}
	sqlIndexes := []string{}

	assertionPolicy, _ := model.assertionModel.GetAssertion("p", "p")
	countTokens := len(assertionPolicy.Tokens)
	fields := make([]string, countTokens+1)
	fields[0] = "id"
	questionMarks := make([]string, countTokens+1)
	questionMarks[0] = "?"

	for i, token := range assertionPolicy.Tokens {
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

func (model *ModelDB) updateRuleDB() error {
	assertionPolicy, _ := model.assertionModel.GetAssertion("p", "p")
	countTokens := len(assertionPolicy.Tokens)
	// frequent inserts in order to avoid "too many SQL variables" (default SQLITE_MAX_VARIABLE_NUMBER = 999)
	batchSize := int(SqliteMaxParameters / (countTokens + 1))

	// TODO code duplication
	fields := make([]string, countTokens+1)
	fields[0] = "id"
	questionMarks := make([]string, countTokens+1)
	questionMarks[0] = "?"
	for i, token := range assertionPolicy.Tokens {
		fields[i+1] = token
		questionMarks[i+1] = "?"
	}

	valuesStatements := []string{}
	values := []interface{}{}

	policy := assertionPolicy.Policy
	policyLen := assertionPolicy.Policy.Len()
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

			if _, err := model.ruleDB.Exec(query, values...); err != nil {
				return err
			}

			valuesStatements = []string{}
			values = []interface{}{}
		}

		i++
	}

	return nil
}

func (model *ModelDB) addRuleToDB(ruleId int, rule []string) error {
	assertionPolicy, _ := model.assertionModel.GetAssertion("p", "p")
	countTokens := len(assertionPolicy.Tokens)
	// TODO code duplication
	fields := make([]string, countTokens+1)
	fields[0] = "id"
	questionMarks := make([]string, countTokens+1)
	questionMarks[0] = "?"
	for i, token := range assertionPolicy.Tokens {
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

	if _, err := model.ruleDB.Exec(query, values...); err != nil {
		return err
	}

	return nil
}

func (model *ModelDB) deleteRulesFromDB(ruleIds []int) error {
	countRules := len(ruleIds)

	questionMarks := []string{}
	values := []interface{}{}

	for i, ruleId := range ruleIds {
		questionMarks = append(questionMarks, "?")
		values = append(values, ruleId)

		if (i%SqliteMaxParameters == 0 && i != 0) || i == countRules-1 {
			query := fmt.Sprintf("DELETE FROM %s WHERE id IN (%s)", RuleTableName, strings.Join(questionMarks, ","))

			if _, err := model.ruleDB.Exec(query, values...); err != nil {
				return err
			}

			questionMarks = []string{}
			values = []interface{}{}
		}
	}

	return nil
}

func (model *ModelDB) deleteRuleFromDB(rule []string) error {
	// TODO make sure len(rule) = len(token)
	assertionPolicy, _ := model.assertionModel.GetAssertion("p", "p")
	countTokens := len(assertionPolicy.Tokens)

	conditions := make([]string, countTokens)
	values := make([]interface{}, countTokens)

	for i, token := range assertionPolicy.Tokens {
		conditions[i] = token + " = ?"
		values[i] = rule[i]
	}

	// TODO make sure conditions is not empty (=> sql syntax error)
	query := fmt.Sprintf("DELETE FROM %s WHERE %s", RuleTableName, strings.Join(conditions, " AND "))

	if _, err := model.ruleDB.Exec(query, values...); err != nil {
		return err
	}

	return nil
}

func (model *ModelDB) clearRuleDB() error {
	query := fmt.Sprintf("DELETE FROM %s", RuleTableName)

	_, err := model.ruleDB.Exec(query)

	return err
}
