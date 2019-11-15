package casbin

import (
	"errors"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

func FlattenExpr(expr *exprpb.Expr) (*exprpb.Expr, error) {
	switch expr.GetExprKind().(type) {
	case *exprpb.Expr_ConstExpr:
		return expr, nil
	case *exprpb.Expr_IdentExpr:
		e := expr.GetIdentExpr()

		return &exprpb.Expr{
			Id: expr.Id,
			ExprKind: &exprpb.Expr_IdentExpr{
				IdentExpr: &exprpb.Expr_Ident{
					Name: EscapeDots(e.Name),
				},
			},
		}, nil
	case *exprpb.Expr_SelectExpr:
		e := expr.GetSelectExpr()

		identExpr, err := flattenSelectExpr(e)
		if err != nil {

		}

		return &exprpb.Expr{
			Id: expr.Id,
			ExprKind: identExpr,
		}, nil
	case *exprpb.Expr_CallExpr:
		e := expr.GetCallExpr()
		if e.Target != nil {
			return nil, errors.New("method call expressions are not supported")
		}

		flatArgs := []*exprpb.Expr{}
		for _, arg := range e.Args {
			flatArg, err := FlattenExpr(arg)
			if err != nil {

			}
			flatArgs = append(flatArgs, flatArg)
		}

		return &exprpb.Expr{
			Id: expr.Id,
			ExprKind: &exprpb.Expr_CallExpr{
				CallExpr: &exprpb.Expr_Call{
					Target:   e.Target,
					Function: e.Function,
					Args:     flatArgs,
				},
			},
		}, nil
	case *exprpb.Expr_ListExpr:
		e := expr.GetListExpr()

		flatElements := []*exprpb.Expr{}
		for _, elem := range e.Elements {
			flatElement, err := FlattenExpr(elem)
			if err != nil {

			}
			flatElements = append(flatElements, flatElement)
		}

		return &exprpb.Expr{
			Id: expr.Id,
			ExprKind: &exprpb.Expr_ListExpr{
				ListExpr: &exprpb.Expr_CreateList{
					Elements: flatElements,
				},
			},
		}, nil
	case *exprpb.Expr_StructExpr:
		return nil, errors.New("struct expressions are not supported")
	case *exprpb.Expr_ComprehensionExpr:
		return nil, errors.New("comprehension expressions are not supported")
	}

	return nil, errors.New("unsupported expression kind")
}

func flattenSelectExpr(exprSelect *exprpb.Expr_Select) (*exprpb.Expr_IdentExpr, error) {
	switch exprSelect.Operand.GetExprKind().(type) {
	case *exprpb.Expr_IdentExpr:
		return &exprpb.Expr_IdentExpr{
			IdentExpr: &exprpb.Expr_Ident{
				Name: EscapeDots(exprSelect.Operand.GetIdentExpr().Name) + "_" + EscapeDots(exprSelect.Field),
			},
		}, nil
	case *exprpb.Expr_SelectExpr:
		identExpr, err := flattenSelectExpr(exprSelect.Operand.GetSelectExpr())
		if err != nil {

		}

		return &exprpb.Expr_IdentExpr{
			IdentExpr: &exprpb.Expr_Ident{
				Name: identExpr.IdentExpr.Name + "_" + EscapeDots(exprSelect.Field),
			},
		}, nil
	default:
		return nil, errors.New("select expressions must be only nested select/ident expressions")
	}
}
