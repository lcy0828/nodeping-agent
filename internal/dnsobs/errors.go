package dnsobs

import "fmt"

type ValidationError struct {
	Field   string
	Code    string
	Message string
}

func (e *ValidationError) Error() string {
	if e == nil {
		return ""
	}
	if e.Field == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

func invalid(field string, code string, message string) error {
	return &ValidationError{Field: field, Code: code, Message: message}
}
