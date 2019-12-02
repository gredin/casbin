package casbin

import (
	"encoding/json"
	_ "errors"
	"github.com/casbin/casbin/v2/util"
	_ "github.com/google/cel-go/common/operators"
	_ "github.com/jeremywohl/flatten"
	_ "reflect"
	"strconv"
	"testing"
	"time"
)



func __Test_Main(t *testing.T) {

	m := map[string]map[string]string{
		"p": {
			"p2": "a",
		},
	}

	e, ok := m["p"]["p"]

	println(e)
	println(ok)

	/*
	expr, err := parser.Parse(common.NewTextSource("keyMatchCustom(r.obj, p.obj) && regexMatch(r.act, p.act)"))

	println(expr)
	println(err)

	exp, _ := govaluate.NewEvaluableExpression("a == b")
	r, _ := exp.Evaluate(map[string]interface{}{
		"a": "1",
		"b": "1",
	})

	_ = r
	*/

	/*
	obj := struct {
		A_b map[string]string
	}{
		map[string]string{"c_d": "e"},
	}

	f, err := FlattenStruct(obj, "")
	if err != nil {
		println(err.Error())
	}
	_ = f

	println(util.ReplaceDots("a.b"))
	println(util.ReplaceDots("a.b.c"))
	println(util.ReplaceDots("a_b.c.d_e"))

	// go test -bench BenchmarkRBACModelMedium -benchmem -run=^$

	env, err := cel.NewEnv(
		cel.Declarations(
			decls.NewIdent("a", decls.Any, nil),
			decls.NewIdent("b", decls.Any, nil),
			//decls.NewIdent("c", decls.String, nil),
			//decls.NewIdent("d", decls.String, nil),
			decls.NewFunction("blabla",
				decls.NewOverload("blabla_string_string",
					[]*exprpb.Type{decls.String, decls.String},
					decls.String)),
		))

	funcs := cel.Functions(
		&functions.Overload{
			Operator: "blabla_string_string",
			Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
				s1, ok := lhs.(types.String)
				if !ok {
					return types.ValOrErr(lhs, "unexpected type '%v' passed to shake_hands", lhs.Type())
				}
				s2, ok := rhs.(types.String)
				if !ok {
					return types.ValOrErr(rhs, "unexpected type '%v' passed to shake_hands", rhs.Type())
				}
				return types.String(
					fmt.Sprintf("%s and %s are shaking hands.\n", s1, s2))
			}})

	parsed, issues := env.Parse(`blabla(a, b)`)
	if issues != nil && issues.Err() != nil {
		log.Fatalf("parse error: %s", issues.Err())
	}
	checked, issues := env.Check(parsed)
	if issues != nil && issues.Err() != nil {
		log.Fatalf("type-check error: %s", issues.Err())
	}
	prg, err := env.Program(checked, funcs)
	if err != nil {
		log.Fatalf("program construction error: %s", err)
	}

	//expr := parsed.Expr()

	object := struct {
		Owner interface{}
	}{
		Owner: map[string]string {
			"Name": "Jean Proprio",
		},
	}

	flatObj, _ := FlattenStruct(object, "r_obj")
	for k, v:= range flatObj {
		fmt.Printf("%s => %s\n", k, v)
	}

	p, _ := parser.Parse(common.NewTextSource("r.obj.Owner.Name == p.sub && r.act == p.act"))
	flatExp, err := FlattenExpr(p.GetExpr())
	if err != nil {
		println(err.Error())
	}

	expr2, err := PartiallyEvalExpr(flatExp)(flatObj)
	out2, err := parser.Unparse(expr2, p.GetSourceInfo())

	println("---")
	println(out2)
	println("---")

	sql, err := ExprToSQL(expr2)
	println(sql)

	//operators.LogicalNot
	//operators.LogicalOr
	//operators.Equals

	out, _, _ := prg.Eval(map[string]interface{}{
		"a": "1",
		"b": "1",
		"c": "2",
		"d": "2",
	})

	_ = out
	//println(out.Value())

	_ = prg

	exp, err := govaluate.NewEvaluableExpression("(r == p) && r.Sub == p.Sub")

	if err != nil {
		println(err.Error())
	}

	tokens := exp.Tokens()
	vars := exp.Vars()
	_ = vars
	_ = tokens

	//govaluate.
	*/

	/*
	enforcer, err := NewEnforcer("model.conf", "policy.csv")

	if err != nil {
		println(err.Error())
	}

	//enforcer.AddFunction("isTimeInRange", IsTimeInRangeFunc)

	subjects := []string{
		"user:alice@Company1.com",
		"user:bob@Company1.com",
		"account:Company1Marketing",
		"account:Company1Legal",
		"corp:Company1",
		"user:anne@Company2.com",
		"user:bernard@Company2.com",
		"account:Company2Legal",
		"account:Company2Marketing",
		"corp:Company2",
	}

	objects := []string{"Gucci", "Calvin Klein", "Burberry", "Perfume", "Clothes", "Cosmetics"}

	for _, o := range objects {
		fmt.Println(o)

		for _, s := range subjects {
			isGranted, _ := enforcer.Enforce(s, o, "read")

			if !isGranted {
				continue
			}

			fmt.Println(s)
		}

		fmt.Println()
	}
	*/
}

func IsTimeInRange(t time.Time, yearMin int, yearMax int) bool {
	year := t.Year()

	return yearMin <= year && year <= yearMax
}

func IsTimeInRangeFunc(args ...interface{}) (interface{}, error) {
	t, _ := args[0].(time.Time)
	yearMin, _ := strconv.Atoi(args[1].(string))
	yearMax, _ := strconv.Atoi(args[2].(string))

	return (bool)(IsTimeInRange(t, yearMin, yearMax)), nil
}

type User struct {
	Id string
}

type Object struct {
	Site     string
	Category string
	Brand    string
	Time     time.Time
}

// https://github.com/hashicorp/terraform/blob/master/flatmap/flatten.go

func EscapeMerger(top bool, prefix, subkey string) string {
	key := prefix

	if top {
		key += util.ReplaceDots(subkey)
	} else {
		key += "_" + util.ReplaceDots(subkey)
	}

	return key
}

func FlattenStruct(o interface{}, prefix string) (map[string]interface{}, error) {
	b, err := json.Marshal(o)
	if err != nil {
		println(err.Error())
	}

	var nested map[string]interface{}
	err = json.Unmarshal(b, &nested)
	if err != nil {
		println(err.Error())
	}

	return Flatten(nested, prefix+"_", FuncMerger(EscapeMerger))

	/*
	reflectType := reflect.TypeOf(s).Elem()
	reflectValue := reflect.ValueOf(s).Elem()

	for i := 0; i < reflectType.NumField(); i++ {
		typeName := reflectType.Field(i).Name

		valueType := reflectValue.Field(i).Type()
		valueValue := reflectValue.Field(i).Interface()

		switch reflectValue.Field(i).Kind() {
		case reflect.String:
			fmt.Printf("%s : %s(%s)\n", typeName, valueValue, valueType)
		case reflect.Int32:
			fmt.Printf("%s : %i(%s)\n", typeName, valueValue, valueType)
		case reflect.Struct:
			fmt.Printf("%s : it is %s\n", typeName, valueType)
			display(&valueValue)
			v := valueValue := reflectValue.Field(i).Addr()
			display(v.Interface())
		}

	}
	*/
}
