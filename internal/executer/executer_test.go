package executer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExec(t *testing.T) {
	executer := NewExecuter()
	ret, err := executer.Exec("ls", "-lat")
	assert.NotNil(t, ret)
	assert.Nil(t, err)
}
