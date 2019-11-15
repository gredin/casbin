package casbin

import (
	"errors"
	"github.com/golang/protobuf/ptypes/struct"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// must only be applied to a flatten expression (containing no select expression)
func PartiallyEvalExpr(expr *exprpb.Expr) func(flattenRequest map[string]interface{}) (*exprpb.Expr, error) {
	return func(flattenRequest map[string]interface{}) (*exprpb.Expr, error) {
		return partiallyEval(expr, flattenRequest)
	}
}

func partiallyEval(expr *exprpb.Expr, flatRequest map[string]interface{}) (*exprpb.Expr, error) {
	switch expr.GetExprKind().(type) {
	case *exprpb.Expr_ConstExpr:
		return expr, nil
	case *exprpb.Expr_IdentExpr:
		e := expr.GetIdentExpr()

		val, ok := flatRequest[e.Name]
		if !ok {
			return expr, nil
		}

		return exprLiteral(expr.Id, val)
	case *exprpb.Expr_CallExpr:
		e := expr.GetCallExpr()

		newArgs := []*exprpb.Expr{}
		for _, arg := range e.Args {
			newArg, err := partiallyEval(arg, flatRequest)
			if err != nil {

			}
			newArgs = append(newArgs, newArg)
		}

		return &exprpb.Expr{
			Id: expr.Id,
			ExprKind: &exprpb.Expr_CallExpr{
				CallExpr: &exprpb.Expr_Call{
					Target:   e.Target,
					Function: e.Function,
					Args:     newArgs,
				},
			},
		}, nil
	case *exprpb.Expr_ListExpr:
		e := expr.GetListExpr()

		newElements := []*exprpb.Expr{}
		for _, elem := range e.Elements {
			newElement, err := partiallyEval(elem, flatRequest)
			if err != nil {

			}
			newElements = append(newElements, newElement)
		}

		return &exprpb.Expr{
			Id: expr.Id,
			ExprKind: &exprpb.Expr_ListExpr{
				ListExpr: &exprpb.Expr_CreateList{
					Elements: newElements,
				},
			},
		}, nil
	case *exprpb.Expr_SelectExpr:
		return nil, errors.New("unflatten select expressions are not supported")
	case *exprpb.Expr_StructExpr:
		return nil, errors.New("struct expressions are not supported")
	case *exprpb.Expr_ComprehensionExpr:
		return nil, errors.New("comprehension expressions are not supported")
	}

	return nil, errors.New("unsupported expression kind")
}

// slightly adapted from ExprLiteral located in github.com/google/cel-go@v0.3.2/test/expr.go
func exprLiteral(id int64, value interface{}) (*exprpb.Expr, error) {
	var literal *exprpb.Constant

	switch value.(type) {
	case bool:
		literal = &exprpb.Constant{ConstantKind: &exprpb.Constant_BoolValue{
			BoolValue: value.(bool)}}
	case int64:
		literal = &exprpb.Constant{ConstantKind: &exprpb.Constant_Int64Value{
			Int64Value: value.(int64)}}
	case uint64:
		literal = &exprpb.Constant{ConstantKind: &exprpb.Constant_Uint64Value{
			Uint64Value: value.(uint64)}}
	case float64:
		literal = &exprpb.Constant{ConstantKind: &exprpb.Constant_DoubleValue{
			DoubleValue: value.(float64)}}
	case string:
		literal = &exprpb.Constant{ConstantKind: &exprpb.Constant_StringValue{
			StringValue: value.(string)}}
	case structpb.NullValue:
		literal = &exprpb.Constant{ConstantKind: &exprpb.Constant_NullValue{
			NullValue: value.(structpb.NullValue)}}
	case []byte:
		literal = &exprpb.Constant{ConstantKind: &exprpb.Constant_BytesValue{
			BytesValue: value.([]byte)}}
	default:
		return nil, errors.New("literal type not implemented")
	}

	return &exprpb.Expr{Id: id, ExprKind: &exprpb.Expr_ConstExpr{ConstExpr: literal}}, nil
}
