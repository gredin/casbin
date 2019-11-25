package casbin

import (
	"errors"
	"github.com/google/cel-go/common/operators"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"strconv"
)

const (
	AllCondition  = "1=1"
	NoneCondition = "1=0"
)

// ref: visitConst in github.com/google/cel-go@v0.3.2/parser/unparser.go
func ExprToSQL(expr *exprpb.Expr) (string, error) {
	switch expr.GetExprKind().(type) {
	case *exprpb.Expr_ConstExpr:
		e := expr.GetConstExpr()
		
		switch e.ConstantKind.(type) {
		case *exprpb.Constant_BoolValue:
			return strconv.FormatBool(e.GetBoolValue()), nil
		case *exprpb.Constant_DoubleValue:
			return strconv.FormatFloat(e.GetDoubleValue(), 'g', -1, 64), nil
		case *exprpb.Constant_Int64Value:
			return strconv.FormatInt(e.GetInt64Value(), 10), nil
		case *exprpb.Constant_NullValue:
			return "null", nil
		case *exprpb.Constant_StringValue:
			return strconv.Quote(e.GetStringValue()), nil
		case *exprpb.Constant_Uint64Value:
			return strconv.FormatUint(e.GetUint64Value(), 10), nil
		case *exprpb.Constant_BytesValue:
			return "", errors.New("bytes not supported")
		default:
			return "", errors.New("unimplemented constant expression kind")
		}
	case *exprpb.Expr_IdentExpr:
		e := expr.GetIdentExpr()

		return e.Name, nil // TODO escape characters?
	case *exprpb.Expr_SelectExpr:
		return "", errors.New("select expression not supported")
	case *exprpb.Expr_CallExpr:
		e := expr.GetCallExpr()

		switch e.Function {
		case operators.In:
			return AllCondition, nil
		case operators.LogicalAnd:
			left, err := ExprToSQL(e.Args[0])
			if err != nil {
				return "", err
			}
			right, err := ExprToSQL(e.Args[1])
			if err != nil {
				return "", err
			}

			if left == AllCondition {
				return right, nil
			} else if right == AllCondition {
				return left, nil
			}

			return left + " AND " + right, nil
		case operators.LogicalOr:
			left, err := ExprToSQL(e.Args[0])
			if err != nil {
				return "", err
			}
			right, err := ExprToSQL(e.Args[1])
			if err != nil {
				return "", err
			}

			if left == AllCondition || right == AllCondition {
				return AllCondition, nil
			}

			return left + " OR " + right, nil
		case operators.Equals:
			left, err := ExprToSQL(e.Args[0])
			if err != nil {
				return "", err
			}
			right, err := ExprToSQL(e.Args[1])
			if err != nil {
				return "", err
			}

			return left + " = " + right, nil
		//case operators.LogicalNot:
		//	return NoneCondition
		}

		return AllCondition, nil
		//return "", errors.New("call expression not supported")
	case *exprpb.Expr_ListExpr:
		_ = expr.GetListExpr()
		return "", errors.New("list expression not supported")
	case *exprpb.Expr_StructExpr:
		_ = expr.GetStructExpr()
		return "", errors.New("struct expression not supported")
	case *exprpb.Expr_ComprehensionExpr:
		_ = expr.GetComprehensionExpr()
		return "", errors.New("comprehension expression not supported")
	}

	return "", errors.New("unimplemented expression kind")
}
