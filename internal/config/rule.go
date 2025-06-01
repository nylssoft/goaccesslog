package config

import (
	"errors"
	"log"
	"strconv"
	"strings"
	"unicode"
)

// EXPR := OPERATOR '(' PROPERTY ',' VALUES ')' | EXPR 'and' EXPR
// VALUES := DIGIT | STRING | VALUES ',' VALUES
// STRING := "'" CHAR "'"
// DIGIT := 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9
// OPERATOR := eq | ne | gt | ge | lt | le | contains | starts-with | ends-with
// PROPERTY := status | uri | ip

// public

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

// private

var operatorMap map[string]Operator = map[string]Operator{
	"eq":          OPR_EQ,
	"ne":          OPR_NE,
	"ge":          OPR_GE,
	"gt":          OPR_GT,
	"le":          OPR_LE,
	"lt":          OPR_LT,
	"contains":    OPR_IN,
	"starts-with": OPR_STARTS,
	"ends-with":   OPR_ENDS,
}

var propertyMap map[string]Property = map[string]Property{
	"status": PROP_STATUS,
	"uri":    PROP_URI,
	"ip":     PROP_IP,
}

func evaluateExpression(expr Expression, data map[Property]any) bool {
	val := data[expr.prop]
	for _, arg := range expr.values {
		// or conjunction for argument list
		if evaluateExpressionValue(expr, val, arg) {
			return true
		}
	}
	return false
}

func evaluateExpressionValue(expr Expression, val any, arg any) bool {
	switch v := val.(type) {
	case int:
		return evaluateIntExpressionValue(expr, v, arg.(int))
	case string:
		return evaluateStringExpressionValue(expr, v, arg.(string))
	}
	return false
}

func evaluateStringExpressionValue(expr Expression, val string, arg string) bool {
	switch expr.op {
	case OPR_EQ:
		return val == arg
	case OPR_NE:
		return val != arg
	case OPR_IN:
		return strings.Contains(val, arg)
	case OPR_STARTS:
		return strings.HasPrefix(val, arg)
	case OPR_ENDS:
		return strings.HasSuffix(val, arg)
	default:
		log.Println("WARN: invalid operator used in condition")
	}
	return false
}

func evaluateIntExpressionValue(expr Expression, val int, arg int) bool {
	switch expr.op {
	case OPR_EQ:
		return val == arg
	case OPR_NE:
		return val != arg
	case OPR_GE:
		return val >= arg
	case OPR_GT:
		return val > arg
	case OPR_LE:
		return val <= arg
	case OPR_LT:
		return val < arg
	default:
		log.Println("WARN: invalid operator used in condition")
	}
	return false
}

func parseExpr(str string, idx int) ([]Expression, error) {
	var ret []Expression
	var op Operator
	var prop Property
	var values []any
	var ok bool
	op, idx, ok = parseFunction(str, idx)
	if !ok {
		return ret, errors.New("cannot parse function " + str + " position" + strconv.Itoa(idx))
	}
	idx, ok = matchRune(str, idx, '(')
	if !ok {
		return ret, errors.New("missing ( " + str + " position" + strconv.Itoa(idx))
	}
	prop, idx, ok = parseProperty(str, idx)
	if !ok {
		return ret, errors.New("cannot parse property " + str + " position" + strconv.Itoa(idx))
	}
	idx, ok = matchRune(str, idx, ',')
	if !ok {
		return ret, errors.New("cannot match , " + str + " position" + strconv.Itoa(idx))
	}
	values, idx, ok = parseValues(str, idx)
	if !ok {
		return ret, errors.New("cannot parse values " + str + " position" + strconv.Itoa(idx))
	}
	idx, ok = matchRune(str, idx, ')')
	if !ok {
		return ret, errors.New("cannot match ) " + str + " position" + strconv.Itoa(idx))
	}
	expression := Expression{op, prop, values}
	ret = append(ret, expression)
	var hasNext bool
	idx, hasNext = matchTerimal(str, idx, "and")
	if hasNext {
		next, err := parseExpr(str, idx)
		if err != nil {
			return ret, err
		}
		ret = append(ret, next...)
	}
	return ret, nil
}

func parseFunction(str string, idx int) (Operator, int, bool) {
	var symbol string
	var ok bool
	var op Operator
	symbol, idx, ok = matchSymbol(str, idx)
	if ok {
		op, ok = operatorMap[symbol]
	}
	return op, idx, ok
}

func parseProperty(str string, idx int) (Property, int, bool) {
	var symbol string
	var ok bool
	var prop Property
	symbol, idx, ok = matchSymbol(str, idx)
	if ok {
		prop, ok = propertyMap[symbol]
	}
	return prop, idx, ok
}

func parseValues(str string, idx int) ([]any, int, bool) {
	var ret []any
	var ok bool = true
	var isString bool
	var hasNext bool
	var val any
	val, idx, isString = matchString(str, idx)
	if !isString {
		var valstr string
		var err error
		valstr, idx, ok = matchDigit(str, idx)
		if ok {
			val, err = strconv.Atoi(valstr)
			if err != nil {
				log.Println("WARN: not a number", valstr)
				ok = false
			}
		}
	}
	if ok {
		ret = append(ret, val)
		idx, hasNext = matchRune(str, idx, ',')
		if hasNext {
			var values []any
			values, idx, ok = parseValues(str, idx)
			if ok {
				ret = append(ret, values...)
			}
		}
	}
	return ret, idx, ok
}

func getRune(str string, idx int) (rune, bool) {
	var r rune
	if idx >= len(str) {
		return r, false
	}
	return rune(str[idx]), true
}

func nextRune(str string, idx int) (rune, int, bool) {
	idx += 1
	r, ok := getRune(str, idx)
	return r, idx, ok
}

func nextNonSpaceRune(str string, idx int) (rune, int, bool) {
	r, ok := getRune(str, idx)
	for ok && unicode.IsSpace(r) {
		r, idx, ok = nextRune(str, idx)
	}
	return r, idx, ok
}

func matchTerimal(str string, idx int, terminal string) (int, bool) {
	var ok bool
	for _, r := range terminal {
		idx, ok = matchRune(str, idx, r)
		if !ok {
			break
		}
	}
	return idx, ok
}

func matchRune(str string, idx int, expected rune) (int, bool) {
	r, idx, ok := nextNonSpaceRune(str, idx)
	if ok {
		if r != expected {
			ok = false
		} else {
			idx++
		}
	}
	return idx, ok
}

func matchDigit(str string, idx int) (string, int, bool) {
	var ret strings.Builder
	r, idx, ok := nextNonSpaceRune(str, idx)
	for ok && unicode.IsDigit(r) {
		ret.WriteRune(r)
		r, idx, ok = nextRune(str, idx)
	}
	return ret.String(), idx, ok
}

func matchString(str string, idx int) (string, int, bool) {
	var ret strings.Builder
	var ok bool
	idx, ok = matchRune(str, idx, '\'')
	if ok {
		var r rune
		r, ok = getRune(str, idx)
		for ok && r != '\'' {
			ret.WriteRune(r)
			r, idx, ok = nextRune(str, idx)
		}
		idx++
	}
	return ret.String(), idx, ok
}

func matchSymbol(str string, idx int) (string, int, bool) {
	var ret strings.Builder
	var ok bool
	var r rune
	r, idx, ok = nextNonSpaceRune(str, idx)
	if ok && unicode.IsLetter(r) {
		ret.WriteRune(r)
		r, idx, ok = nextRune(str, idx)
		for ok && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_') {
			ret.WriteRune(r)
			r, idx, ok = nextRune(str, idx)
		}
	}
	return ret.String(), idx, ok
}
