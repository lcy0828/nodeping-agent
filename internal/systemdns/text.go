package systemdns

import (
	"fmt"
	"unicode"
	"unicode/utf8"
)

func validateTextInput(input []byte) error {
	if !utf8.Valid(input) {
		return fmt.Errorf("input is not valid UTF-8")
	}
	for _, value := range string(input) {
		if value == 0 {
			return fmt.Errorf("input contains a NUL byte")
		}
		if unicode.IsControl(value) && value != '\n' && value != '\r' && value != '\t' {
			return fmt.Errorf("input contains an unsupported control character")
		}
	}
	return nil
}
