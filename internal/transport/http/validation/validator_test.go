package validation

import "testing"

func TestNewValidator_NumericCode(t *testing.T) {
	v := newValidator()

	type request struct {
		Code string `validate:"required,not_blank,numeric_code,min=4,max=12"`
	}

	tests := []struct {
		name    string
		code    string
		wantErr bool
	}{
		{name: "valid", code: "123456", wantErr: false},
		{name: "contains letters", code: "12a456", wantErr: true},
		{name: "contains spaces", code: " 123456 ", wantErr: true},
		{name: "all spaces", code: "      ", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Struct(request{Code: tt.code})
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected error=%t, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestNewValidator_Locale(t *testing.T) {
	v := newValidator()

	type request struct {
		Locale string `validate:"required,locale"`
	}

	tests := []struct {
		name    string
		locale  string
		wantErr bool
	}{
		{name: "language with country underscore", locale: "en_US", wantErr: false},
		{name: "language with country dash", locale: "en-US", wantErr: false},
		{name: "language only", locale: "en", wantErr: false},
		{name: "lowercase country", locale: "en_us", wantErr: true},
		{name: "spaces", locale: " en_US ", wantErr: true},
		{name: "garbage", locale: "english", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Struct(request{Locale: tt.locale})
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected error=%t, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestNewValidator_Timezone(t *testing.T) {
	v := newValidator()

	type request struct {
		Timezone string `validate:"required,timezone"`
	}

	tests := []struct {
		name     string
		timezone string
		wantErr  bool
	}{
		{name: "utc", timezone: "UTC", wantErr: false},
		{name: "kyiv", timezone: "Europe/Kyiv", wantErr: false},
		{name: "kiev alias", timezone: "Europe/Kiev", wantErr: false},
		{name: "invalid", timezone: "Mars/Base", wantErr: true},
		{name: "spaces", timezone: " UTC ", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Struct(request{Timezone: tt.timezone})
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected error=%t, got %v", tt.wantErr, err)
			}
		})
	}
}
