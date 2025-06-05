package rule

import (
	"errors"
	"fmt"
	"log"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

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
	"status":   PROP_STATUS,
	"uri":      PROP_URI,
	"ip":       PROP_IP,
	"protocol": PROP_PROTOCOL,
}

var invalidNumberOperators []Operator = []Operator{OPR_IN, OPR_STARTS, OPR_ENDS}

func evaluateExpression(expr Expression, data map[Property]any) bool {
	val := data[expr.Prop]
	for _, arg := range expr.Values {
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
	switch expr.Op {
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
	switch expr.Op {
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
	var err error
	op, idx, err = parseFunction(str, idx)
	if err != nil {
		return ret, fmt.Errorf("cannot parse function in '%s' at position %d: %s", str, idx, err.Error())
	}
	idx, ok = matchRune(str, idx, '(')
	if !ok {
		return ret, fmt.Errorf("missing '(' in '%s' at position %d", str, idx)
	}
	prop, idx, err = parseProperty(op, str, idx)
	if err != nil {
		return ret, fmt.Errorf("cannot parse property in '%s' at position %d: %s", str, idx, err.Error())
	}
	idx, ok = matchRune(str, idx, ',')
	if !ok {
		return ret, fmt.Errorf("missing ',' in '%s' at position %d", str, idx)
	}
	values, idx, err = parseValues(str, idx, isIntType(prop))
	if err != nil {
		return ret, fmt.Errorf("cannot parse values in '%s' at position %d: %s", str, idx, err.Error())
	}
	idx, ok = matchRune(str, idx, ')')
	if !ok {
		return ret, fmt.Errorf("missing ')' in '%s' at position %d", str, idx)
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

func isIntType(prop Property) bool {
	return prop == PROP_STATUS
}

func parseFunction(str string, idx int) (Operator, int, error) {
	var symbol string
	var ok bool
	var op Operator
	symbol, idx, ok = matchSymbol(str, idx)
	if ok {
		op, ok = operatorMap[symbol]
	}
	if !ok {
		return op, idx, fmt.Errorf("unknown function '%s'", symbol)
	}
	return op, idx, nil
}

func parseProperty(op Operator, str string, idx int) (Property, int, error) {
	var symbol string
	var ok bool
	var prop Property
	symbol, idx, ok = matchSymbol(str, idx)
	if ok {
		prop, ok = propertyMap[symbol]
	}
	if !ok {
		return prop, idx, fmt.Errorf("unknown property '%s'", symbol)
	}
	if isIntType(prop) && slices.Contains(invalidNumberOperators, op) {
		return prop, idx, fmt.Errorf("invalid function for property '%s'", symbol)
	}
	return prop, idx, nil
}

func parseValues(str string, idx int, isIntType bool) ([]any, int, error) {
	var ret []any
	var ok bool = true
	var hasNext bool
	var val any
	if isIntType {
		var valstr string
		var err error
		valstr, idx, ok = matchNumber(str, idx)
		if !ok {
			return ret, idx, errors.New("value is not a number")
		}
		val, err = strconv.Atoi(valstr)
		if err != nil {
			return ret, idx, errors.New("value is not a number")
		}
	} else {
		val, idx, ok = matchString(str, idx)
		if !ok {
			return ret, idx, errors.New("value is not a string")
		}
	}
	ret = append(ret, val)
	idx, hasNext = matchRune(str, idx, ',')
	if hasNext {
		var values []any
		var err error
		values, idx, err = parseValues(str, idx, isIntType)
		if err != nil {
			return ret, idx, err
		}
		ret = append(ret, values...)
	}
	return ret, idx, nil
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

func matchNumber(str string, idx int) (string, int, bool) {
	var ret strings.Builder
	r, idx, ok := nextNonSpaceRune(str, idx)
	ok = ok && unicode.IsDigit(r)
	if ok {
		ret.WriteRune(r)
		var hasNext bool
		r, idx, hasNext = nextRune(str, idx)
		for hasNext && unicode.IsDigit(r) {
			ret.WriteRune(r)
			r, idx, hasNext = nextRune(str, idx)
		}
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
	ok = ok && unicode.IsLetter(r)
	if ok {
		ret.WriteRune(r)
		var hasNext bool
		r, idx, hasNext = nextRune(str, idx)
		for hasNext && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_') {
			ret.WriteRune(r)
			r, idx, hasNext = nextRune(str, idx)
		}
	}
	return ret.String(), idx, ok
}
