package domain

import (
	"context"
	"time"

	"github.com/whagency/core-common/tools"
)

const ProfileDefaultLocale = "en_US"
const ProfileUkraineLocale = "uk_UA"

type Profile struct {
	ID       ID
	UserID   ID
	Country  string
	Timezone string
	Locale   *string
}

// NewProfileForUser creates a new Profile for registration
func NewProfileForUser(userID ID, country string, timezone string) *Profile {
	locale := ProfileDefaultLocale
	if country == UserDefaultCountry {
		locale = ProfileUkraineLocale
	}
	return &Profile{
		UserID:   userID,
		Country:  country,
		Timezone: timezone,
		Locale:   tools.ToPtr(locale),
	}
}

type UpdateProfileParams struct {
	UserID      ID
	FirstName   *string
	LastName    *string
	DateOfBirth *string
	Address     *string
	Locale      *string
	Timezone    *string
}

// ProfileDetails represents the readable profile data for the user.
type ProfileDetails struct {
	FirstName   *string
	LastName    *string
	Country     string
	DateOfBirth *time.Time
	Address     *string
	Locale      *string
	Timezone    *string
}

type ProfileRepository interface {
	Create(context.Context, *Profile) error
	Update(context.Context, UpdateProfileParams) error
	Exists(context.Context, ID) (bool, error)
	FindByUserID(context.Context, ID) (ProfileDetails, error)

	WithTxFromContext(context.Context) ProfileRepository
}
