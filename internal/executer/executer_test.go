package executer

import "testing"

func TestExec(t *testing.T) {
	executer := NewExecuter()
	ret, err := executer.Exec("ls", "-lat")
	assertNotNil(t, ret)
	assertNil(t, err)
}

func assertNotNil(t *testing.T, value any) {
	if value == nil {
		t.Errorf("Expected value must not be nil but is '%v'.", value)
	}
}

func assertNil(t *testing.T, value any) {
	if value != nil {
		t.Errorf("Expected value must be nil but is '%v'.", value)
	}
}
