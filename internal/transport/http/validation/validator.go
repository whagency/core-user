package validation

import (
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-playground/validator/v10"
	appErrors "github.com/whagency/core-common/errorsx"
	commonValidation "github.com/whagency/core-common/http/validation"
	commonRules "github.com/whagency/core-common/validation"
)

var (
	once               sync.Once
	transportValidator *validator.Validate
	_localePattern     = regexp.MustCompile(`^[a-z]{2}(?:[_-][A-Z]{2})?$`)
)

// Validator exposes the shared HTTP transport validator instance.
// Safe for concurrent use after first initialization.
func Validator() *validator.Validate {
	once.Do(func() { transportValidator = newValidator() })
	return transportValidator
}

type Option = commonValidation.Option

// Init allows initializing the singleton with extra options (call once at app bootstrap).
// If called multiple times, only the first call has effect.
func Init(opts ...Option) *validator.Validate {
	once.Do(func() {
		transportValidator = newValidator(opts...)
	})
	return transportValidator
}

// ResetForTests resets the singleton for testing purposes.
func ResetForTests() {
	transportValidator = nil
	once = sync.Once{}
}

func newValidator(opts ...Option) *validator.Validate {
	options := []commonValidation.Option{
		commonValidation.WithTagAlias("identifier", appErrors.ValidationTagFormat),
		commonValidation.WithTagAlias("contact_value", appErrors.ValidationTagFormat),
		commonValidation.WithTagAlias("password", appErrors.ValidationTagWeak),
		commonValidation.WithTagAlias("numeric_code", appErrors.ValidationTagFormat),
		commonValidation.WithTagAlias("locale", appErrors.ValidationTagFormat),
		commonValidation.WithTagAlias("timezone", appErrors.ValidationTagFormat),
	}
	options = append(options, opts...)

	v := commonValidation.MustNew(options...)

	passwordPolicy := commonRules.NewDefaultPasswordPolicy(commonRules.DefaultMinLengthPassword)
	_ = v.RegisterValidation("password", func(fl validator.FieldLevel) bool {
		return passwordPolicy.Validate(fl.Field().String()) == nil
	})
	_ = v.RegisterValidation("numeric_code", func(fl validator.FieldLevel) bool {
		s := fl.Field().String()
		if s == "" || strings.TrimSpace(s) != s {
			return false
		}

		for _, r := range s {
			if r < '0' || r > '9' {
				return false
			}
		}

		return true
	})
	_ = v.RegisterValidation("locale", func(fl validator.FieldLevel) bool {
		s := fl.Field().String()
		if s == "" || strings.TrimSpace(s) != s {
			return false
		}

		return _localePattern.MatchString(s)
	})
	_ = v.RegisterValidation("timezone", func(fl validator.FieldLevel) bool {
		s := fl.Field().String()
		if s == "" || strings.TrimSpace(s) != s {
			return false
		}

		_, err := time.LoadLocation(s)
		return err == nil
	})
	_ = v.RegisterValidation("identifier", func(fl validator.FieldLevel) bool {
		s := fl.Field().String()
		if s == "" {
			return false
		}
		if err := v.Var(s, "email"); err == nil {
			return true
		}
		if err := v.Var(s, "e164"); err == nil {
			return true
		}
		return false
	})
	_ = v.RegisterValidation("contact_value", func(fl validator.FieldLevel) bool {
		parent := fl.Parent().Interface()
		cr, ok := parent.(interface{ GetType() string })
		if !ok {
			return false
		}

		s := strings.TrimSpace(fl.Field().String())
		if s == "" {
			return false
		}

		switch cr.GetType() {
		case "email":
			return v.Var(s, "email") == nil
		case "phone":
			return v.Var(s, "e164") == nil
		default:
			return false
		}
	})

	return v
}
