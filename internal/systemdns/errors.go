package systemdns

import (
	"errors"
	"fmt"
)

// ErrorCode identifies a stable discovery failure category.
type ErrorCode string

const (
	ErrorInvalidInput ErrorCode = "invalid_input"
	ErrorMalformed    ErrorCode = "malformed"
	ErrorTooLarge     ErrorCode = "too_large"
	ErrorTooMany      ErrorCode = "too_many"
	ErrorIO           ErrorCode = "io"
	ErrorCommand      ErrorCode = "command_failed"
	ErrorTimeout      ErrorCode = "timeout"
	ErrorCancelled    ErrorCode = "cancelled"
	ErrorNoResolvers  ErrorCode = "no_resolvers"
	ErrorUnsupported  ErrorCode = "unsupported_platform"
	ErrorSystemAPI    ErrorCode = "system_api"
)

// DiscoveryError is returned for all parse and platform discovery failures.
// Line is one-based and zero when a failure is not tied to textual input.
type DiscoveryError struct {
	Code     ErrorCode
	Platform Platform
	Op       string
	Field    string
	Line     int
	Message  string
	Err      error
}

func (e *DiscoveryError) Error() string {
	if e == nil {
		return ""
	}
	where := e.Op
	if e.Field != "" {
		if where != "" {
			where += "."
		}
		where += e.Field
	}
	if e.Line > 0 {
		where += fmt.Sprintf(" (line %d)", e.Line)
	}
	if where == "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("%s: %s: %s", e.Code, where, e.Message)
}

func (e *DiscoveryError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func discoveryError(code ErrorCode, platform Platform, op, field string, line int, message string, err error) error {
	return &DiscoveryError{
		Code:     code,
		Platform: platform,
		Op:       op,
		Field:    field,
		Line:     line,
		Message:  message,
		Err:      err,
	}
}

// IsErrorCode reports whether err contains a DiscoveryError with code.
func IsErrorCode(err error, code ErrorCode) bool {
	var discoveryErr *DiscoveryError
	return errors.As(err, &discoveryErr) && discoveryErr.Code == code
}
