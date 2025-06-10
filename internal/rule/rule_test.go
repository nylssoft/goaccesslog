package rule

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCondition(t *testing.T) {
	expr, err := ParseCondition("")
	assert.NotNil(t, err)
	assert.Nil(t, expr)

	expr, err = ParseCondition("unknown")
	assert.NotNil(t, err)
	assert.Nil(t, expr)

	expr, err = ParseCondition("eq")
	assert.NotNil(t, err)
	assert.Nil(t, expr)

	expr, err = ParseCondition("eq(")
	assert.NotNil(t, err)
	assert.Nil(t, expr)

	expr, err = ParseCondition("eq(unknown")
	assert.NotNil(t, err)
	assert.Nil(t, expr)

	expr, err = ParseCondition("contains(status")
	assert.NotNil(t, err)
	assert.Nil(t, expr)

	expr, err = ParseCondition("eq(status")
	assert.NotNil(t, err)
	assert.Nil(t, expr)

	expr, err = ParseCondition("eq(status,")
	assert.NotNil(t, err)
	assert.Nil(t, expr)

	expr, err = ParseCondition("eq(status,999999999999999999999999")
	assert.NotNil(t, err)
	assert.Nil(t, expr)

	expr, err = ParseCondition("eq(status,400")
	assert.NotNil(t, err)
	assert.Nil(t, expr)

	expr, err = ParseCondition("contains(ip,400")
	assert.NotNil(t, err)
	assert.Nil(t, expr)

	expr, err = ParseCondition("contains(ip,'127")
	assert.NotNil(t, err)
	assert.Nil(t, expr)

	expr, err = ParseCondition("contains(ip,'127'")
	assert.NotNil(t, err)
	assert.Nil(t, expr)

	expr, err = ParseCondition("contains(ip,'127')")
	assert.Nil(t, err)
	assert.NotNil(t, expr)
	assert.Equal(t, 1, len(expr))
	assert.Equal(t, Operator(OPR_IN), expr[0].Op)
	assert.Equal(t, Property(PROP_IP), expr[0].Prop)
	assert.Equal(t, 1, len(expr[0].Values))
	assert.Equal(t, "127", expr[0].Values[0])

	expr, err = ParseCondition("    contains  (   ip   ,   '127   '   )   ")
	assert.Nil(t, err)
	assert.NotNil(t, expr)
	assert.Equal(t, 1, len(expr))
	assert.Equal(t, Operator(OPR_IN), expr[0].Op)
	assert.Equal(t, Property(PROP_IP), expr[0].Prop)
	assert.Equal(t, 1, len(expr[0].Values))
	assert.Equal(t, "127   ", expr[0].Values[0])

	expr, err = ParseCondition("contains(ip,'127',')")
	assert.NotNil(t, err)
	assert.Nil(t, expr)

	expr, err = ParseCondition("contains(ip,'127','88.8') and eq(status,400,404,500)")
	assert.Nil(t, err)
	assert.NotNil(t, expr)
	assert.Equal(t, 2, len(expr))
	assert.Equal(t, Operator(OPR_IN), expr[0].Op)
	assert.Equal(t, Property(PROP_IP), expr[0].Prop)
	assert.Equal(t, 2, len(expr[0].Values))
	assert.Equal(t, "127", expr[0].Values[0])
	assert.Equal(t, "88.8", expr[0].Values[1])
	assert.Equal(t, Operator(OPR_EQ), expr[1].Op)
	assert.Equal(t, Property(PROP_STATUS), expr[1].Prop)
	assert.Equal(t, 3, len(expr[1].Values))
	assert.Equal(t, 400, expr[1].Values[0])
	assert.Equal(t, 404, expr[1].Values[1])
	assert.Equal(t, 500, expr[1].Values[2])

	expr, err = ParseCondition("contains(ip,'127') and unknown")
	assert.NotNil(t, err)
	assert.Nil(t, expr)

	expr, err = ParseCondition("contains(ip,'127') or")
	assert.NotNil(t, err)
	assert.Nil(t, expr)

}

func TestEvaluateExpression(t *testing.T) {
	expr, err := ParseCondition("ge(status,400) and contains(uri,'1.1.1.1') and starts-with(protocol, 'GET')")
	require.Nil(t, err)
	data := make(map[Property]any)
	ret := EvaluateExpressions(expr, data)
	assert.False(t, ret)

	data[Property(PROP_STATUS)] = 400
	data[Property(PROP_URI)] = "1.1.1.1"
	data[Property(PROP_PROTOCOL)] = "GET"
	data[Property(PROP_IP)] = "127.0.0.1"
	ret = EvaluateExpressions(expr, data)
	assert.True(t, ret)

	expr, err = ParseCondition("eq(status,400)")
	require.Nil(t, err)
	ret = EvaluateExpressions(expr, data)
	assert.True(t, ret)

	expr, err = ParseCondition("ne(status,400)")
	require.Nil(t, err)
	ret = EvaluateExpressions(expr, data)
	assert.False(t, ret)

	expr, err = ParseCondition("gt(status,400)")
	require.Nil(t, err)
	ret = EvaluateExpressions(expr, data)
	assert.False(t, ret)

	expr, err = ParseCondition("lt(status,400)")
	require.Nil(t, err)
	ret = EvaluateExpressions(expr, data)
	assert.False(t, ret)

	expr, err = ParseCondition("le(status,400)")
	require.Nil(t, err)
	ret = EvaluateExpressions(expr, data)
	assert.True(t, ret)

	expr, err = ParseCondition("starts-with(ip,'127.')")
	require.Nil(t, err)
	ret = EvaluateExpressions(expr, data)
	assert.True(t, ret)

	expr, err = ParseCondition("ends-with(ip,'127.')")
	require.Nil(t, err)
	ret = EvaluateExpressions(expr, data)
	assert.False(t, ret)

	expr, err = ParseCondition("contains(ip,'127.')")
	require.Nil(t, err)
	ret = EvaluateExpressions(expr, data)
	assert.True(t, ret)

	expr, err = ParseCondition("eq(ip,'127.')")
	require.Nil(t, err)
	ret = EvaluateExpressions(expr, data)
	assert.False(t, ret)

	expr, err = ParseCondition("ne(ip,'127.')")
	require.Nil(t, err)
	ret = EvaluateExpressions(expr, data)
	assert.True(t, ret)

	expr, err = ParseCondition("ge(ip,'127.')")
	require.Nil(t, err)
	ret = EvaluateExpressions(expr, data)
	assert.True(t, ret)

	expr, err = ParseCondition("gt(ip,'127.')")
	require.Nil(t, err)
	ret = EvaluateExpressions(expr, data)
	assert.True(t, ret)

	expr, err = ParseCondition("le(ip,'127.')")
	require.Nil(t, err)
	ret = EvaluateExpressions(expr, data)
	assert.False(t, ret)

	expr, err = ParseCondition("lt(ip,'127.')")
	require.Nil(t, err)
	ret = EvaluateExpressions(expr, data)
	assert.False(t, ret)

}
