package ufw

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUfw(t *testing.T) {
	var e mockExecutor = mockExecutor{
		ret: `Status: active

To                         Action      From
--                         ------      ----
Anywhere                   REJECT      178.128.20.144             # unittest
Anywhere                   REJECT      45.82.78.254               # unittest
Anywhere                   REJECT      204.76.203.219
Anywhere                   REJECT      176.65.148.236             # unittest
OpenSSH                    DENY        Anywhere`,
		err: nil,
	}

	ufw := NewUfw(&e, "unittest", time.Hour, 10)
	assert.NotNil(t, ufw)

	ufw.Init()

	// 3 IPs rejected, 1 IP skipped
	rejected := ufw.IsRejected("178.128.20.144")
	assert.True(t, rejected)
	rejected = ufw.IsRejected("45.82.78.254")
	assert.True(t, rejected)
	rejected = ufw.IsRejected("176.65.148.236")
	assert.True(t, rejected)
	rejected = ufw.IsRejected("204.76.203.219")
	assert.False(t, rejected)

	// release a single IP
	ufw.Release("178.128.20.144")
	rejected = ufw.IsRejected("178.128.20.144")
	assert.False(t, rejected)

	// release all IPs
	ufw.ReleaseAll()
	rejected = ufw.IsRejected("178.128.20.144")
	assert.False(t, rejected)
	rejected = ufw.IsRejected("45.82.78.254")
	assert.False(t, rejected)
	rejected = ufw.IsRejected("176.65.148.236")
	assert.False(t, rejected)

	ufw = NewUfw(&e, "unittest", time.Second, 3)
	ufw.Init()
	time.Sleep(time.Second * 2)
	// all IPs expired, therefore released
	ufw.ReleaseIfExpired()
	rejected = ufw.IsRejected("178.128.20.144")
	assert.False(t, rejected)
	rejected = ufw.IsRejected("45.82.78.254")
	assert.False(t, rejected)
	rejected = ufw.IsRejected("176.65.148.236")
	assert.False(t, rejected)

	// reject IP four times, totally delayed for 1 << 3 seconds == 8 seconds
	ufw.Reject("1.1.1.1")
	ufw.Reject("1.1.1.1")
	ufw.Reject("1.1.1.1")
	ufw.Reject("1.1.1.1")
	assert.True(t, ufw.IsRejected("1.1.1.1"))
	time.Sleep(time.Second * 3)
	ufw.ReleaseIfExpired()
	assert.True(t, ufw.IsRejected("1.1.1.1"))
	time.Sleep(time.Second * 6)
	ufw.ReleaseIfExpired()
	assert.False(t, ufw.IsRejected("1.1.1.1"))

	// error handling
	e.err = errors.New("simulate error")
	ufw.Init()
	assert.False(t, ufw.Reject("1.1.1.1"))
}

type mockExecutor struct {
	ret string
	err error
}

func (e *mockExecutor) Exec(cmdName string, args ...string) ([]byte, error) {
	return []byte(e.ret), e.err
}
