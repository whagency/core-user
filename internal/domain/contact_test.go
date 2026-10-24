package domain

import "testing"

func TestNormalizeContactValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "lowercases an email", in: "Alice@Example.COM", want: "alice@example.com"},
		{name: "trims what a paste brings along", in: "  alice@example.com \n", want: "alice@example.com"},
		{name: "both at once", in: " Alice@Example.com ", want: "alice@example.com"},
		{name: "leaves an already canonical value alone", in: "alice@example.com", want: "alice@example.com"},
		{name: "an e164 number has no case to change", in: "+380501234567", want: "+380501234567"},
		{name: "empty stays empty", in: "   ", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeContactValue(tt.in); got != tt.want {
				t.Fatalf("NormalizeContactValue(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// Storage and lookup must land on the same string, or a value written under one
// form stops being findable under the other.
func TestNormalizeContactValueIsIdempotent(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"Alice@Example.COM", " a@b.c ", "+380501234567"} {
		once := NormalizeContactValue(in)
		if twice := NormalizeContactValue(once); twice != once {
			t.Fatalf("normalizing %q twice changed it: %q then %q", in, once, twice)
		}
	}
}
