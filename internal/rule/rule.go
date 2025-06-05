package rule

// EXPR := OPERATOR '(' PROPERTY ',' VALUES ')' | EXPR 'and' EXPR
// VALUES := DIGIT | STRING | VALUES ',' VALUES
// STRING := "'" CHAR "'"
// DIGIT := 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9
// OPERATOR := eq | ne | gt | ge | lt | le | contains | starts-with | ends-with
// PROPERTY := status | uri | ip

type Operator int

type Property int

type Expression struct {
	op     Operator
	prop   Property
	values []any
}

const (
	OPR_EQ = iota
	OPR_NE
	OPR_GE
	OPR_GT
	OPR_LE
	OPR_LT
	OPR_IN
	OPR_STARTS
	OPR_ENDS
)

const (
	PROP_STATUS = iota
	PROP_URI
	PROP_IP
	PROP_PROTOCOL
)

func ParseCondition(str string) ([]Expression, error) {
	return parseExpr(str, 0)
}

func EvaluateExpressions(expressions []Expression, data map[Property]any) bool {
	for _, expr := range expressions {
		// and conjunction for expression list
		if !evaluateExpression(expr, data) {
			return false
		}
	}
	return true
}
