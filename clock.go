package oauth1

import (
	"time"
)

// clock provides a interface for current time providers. A Clock can be used
// in place of calling time.Now() directly.
type clock interface {
	Now() time.Time
}

type realClock struct{}

// newRealClock returns a clock which delegates calls to the time package.
func newRealClock() clock {
	return &realClock{}
}

func (c *realClock) Now() time.Time {
	return time.Now()
}
