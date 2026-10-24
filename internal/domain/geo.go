package domain

const (
	UserDefaultCountry  = "UA"
	UserDefaultTimezone = "Europe/Kyiv"
)

type GeoInfo struct {
	IP             string
	CountryCode    string
	CountryName    string
	Continent      string
	City           string
	Region         string
	Latitude       *float64
	Longitude      *float64
	TimeZone       string
	PostalCode     string
	AccuracyRadius uint16
}

type AnonymousInfo struct {
	IsAnonymous        bool
	IsAnonymousVPN     bool
	IsHostingProvider  bool
	IsPublicProxy      bool
	IsResidentialProxy bool
	IsTorExitNode      bool
	Network            string
}

// GeoController provides receiving geo data such as location info, VPN.
type GeoController interface {
	GetGeoInfo(string) (*GeoInfo, error)
	GetAnonymousInfo(string) (*AnonymousInfo, error)
}

// GeoService defines the interface for managing geo service in the data layer.
type GeoService interface {
	GetGeoInfo(string) (*GeoInfo, error)
	GetAnonymousInfo(string) (*AnonymousInfo, error)
}
