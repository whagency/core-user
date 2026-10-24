package errors

import "testing"

// The codes are an iota block, so inserting a constant into a group renumbers
// every constant below it. The frontend is written against these numbers and the
// README documents them, which makes a silent shift a contract break that
// compiles cleanly.
//
// Pinning the ends is enough to catch it: the first, the last, and the boundary
// where a well-meaning insert into the Account* group would land.
func TestServiceErrorCodesAreStable(t *testing.T) {
	tests := []struct {
		name string
		got  int
		want int
	}{
		{name: "CodeInvalidError", got: CodeInvalidError, want: 100001},
		{name: "AccountInvalidCredentialsError", got: AccountInvalidCredentialsError, want: 100006},
		{name: "AccountContactUnverifiedError", got: AccountContactUnverifiedError, want: 100010},
		{name: "RecaptchaValidationError", got: RecaptchaValidationError, want: 100024},
		{name: "AccountLoginAttemptsExceededError", got: AccountLoginAttemptsExceededError, want: 100025},
	}

	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %d, want %d -- a code moved, which breaks the frontend contract; new codes go at the end of the block", tt.name, tt.got, tt.want)
		}
	}
}

// Every code needs a template, or New() would hand back a zero-valued response.
func TestEveryCodeHasATemplate(t *testing.T) {
	templates := Templates()

	for code := CodeInvalidError; code <= AccountLoginAttemptsExceededError; code++ {
		tpl, ok := templates[code]
		if !ok {
			t.Errorf("code %d has no template", code)
			continue
		}
		if tpl.Message == "" {
			t.Errorf("code %d has an empty message", code)
		}
		if tpl.HTTPStatus == 0 {
			t.Errorf("code %d has no HTTP status", code)
		}
	}
}
