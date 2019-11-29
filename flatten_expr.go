package casbin

import (
	"errors"
	"github.com/casbin/casbin/v2/util"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

func FlattenExpr(expr *exprpb.Expr) (*exprpb.Expr, []string, error) {
	identifiers := map[string]bool{}

	flatExpr, err := flattenExpr(expr, identifiers)

	uniqueIdentifiers := make([]string, len(identifiers))
	i := 0
	for identifier, _ := range identifiers {
		uniqueIdentifiers[i] = identifier
		i++
	}

	return flatExpr, uniqueIdentifiers, err
}

func flattenExpr(expr *exprpb.Expr, identifiers map[string]bool) (*exprpb.Expr, error) {
	switch expr.GetExprKind().(type) {
	case *exprpb.Expr_ConstExpr:
		return expr, nil
	case *exprpb.Expr_IdentExpr:
		e := expr.GetIdentExpr()

		newName := util.ReplaceDots(e.Name)

		identifiers[newName] = true

		return &exprpb.Expr{
			Id: expr.Id,
			ExprKind: &exprpb.Expr_IdentExpr{
				IdentExpr: &exprpb.Expr_Ident{
					Name: newName,
				},
			},
		}, nil
	case *exprpb.Expr_SelectExpr:
		e := expr.GetSelectExpr()

		identExpr, err := flattenSelectExpr(e)
		if err != nil {
			// TODO
		}

		identifiers[identExpr.IdentExpr.Name] = true

		return &exprpb.Expr{
			Id:       expr.Id,
			ExprKind: identExpr,
		}, nil
	case *exprpb.Expr_CallExpr:
		e := expr.GetCallExpr()
		if e.Target != nil {
			return nil, errors.New("method call expressions are not supported")
		}

		flatArgs := []*exprpb.Expr{}
		for _, arg := range e.Args {
			flatArg, err := flattenExpr(arg, identifiers)
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
			flatElement, err := flattenExpr(elem, identifiers)
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
				Name: util.ReplaceDots(exprSelect.Operand.GetIdentExpr().Name) + "_" + util.ReplaceDots(exprSelect.Field),
			},
		}, nil
	case *exprpb.Expr_SelectExpr:
		identExpr, err := flattenSelectExpr(exprSelect.Operand.GetSelectExpr())
		if err != nil {

		}

		return &exprpb.Expr_IdentExpr{
			IdentExpr: &exprpb.Expr_Ident{
				Name: identExpr.IdentExpr.Name + "_" + util.ReplaceDots(exprSelect.Field),
			},
		}, nil
	default:
		return nil, errors.New("select expressions must be only nested select/ident expressions")
	}
}
