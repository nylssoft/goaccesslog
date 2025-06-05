package executer

type Executer interface {
	Exec(cmdName string, args ...string) ([]byte, error)
}

func NewExecuter() Executer {
	var e executor_impl
	return &e
}
