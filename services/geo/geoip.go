package geo

import (
	"fmt"
	"net/netip"
	"sync"

	"user-service/internal/domain"

	"github.com/oschwald/geoip2-golang/v2"
)

var (
	once        sync.Once
	geoInstance *Service
)

type Service struct {
	dbGeo       *geoip2.Reader
	dbAnonymous *geoip2.Reader
}

// newGeoService initializes a new Geo Service with the required databases.
func newGeoService() (*Service, error) {
	dbGeo, errGeo := geoip2.Open("data/geoip/GeoLite2-City.mmdb")
	if errGeo != nil {
		return nil, fmt.Errorf("[newGeoService][err: %w]", errGeo)
	}

	dbAnonymous, errAnonymous := geoip2.Open("data/geoip/GeoIP2-Anonymous-IP.mmdb")
	if errAnonymous != nil {
		return nil, fmt.Errorf("[newGeoService][err: %w]", errAnonymous)
	}

	return &Service{
		dbGeo:       dbGeo,
		dbAnonymous: dbAnonymous,
	}, nil
}

// GetGeoService returns a singleton instance of the Geo Service.
func GetGeoService() (*Service, error) {
	var geoError error
	once.Do(func() {
		geoInstance, geoError = newGeoService()
	})
	return geoInstance, geoError
}

// GetGeoInfo retrieves geographical information for the given IP address.
func (s Service) GetGeoInfo(ip string) (*domain.GeoInfo, error) {
	ipAddress, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("[GeoService:GetGeoInfo][err: %w]", err)
	}

	record, err := s.dbGeo.City(ipAddress)
	if err != nil {
		return nil, fmt.Errorf("[GeoService:GetGeoInfo][err: %w]", err)
	}
	if !record.HasData() {
		return nil, fmt.Errorf("[GeoService:GetGeoInfo][err: No data found for IP %s]", ip)
	}

	region := ""
	if len(record.Subdivisions) > 0 {
		region = record.Subdivisions[0].Names.English
	}

	return &domain.GeoInfo{
		IP:             ip,
		CountryCode:    record.Country.ISOCode,
		CountryName:    record.Country.Names.English,
		Continent:      record.Continent.Names.English,
		City:           record.City.Names.English,
		Region:         region,
		Latitude:       record.Location.Latitude,
		Longitude:      record.Location.Longitude,
		TimeZone:       record.Location.TimeZone,
		PostalCode:     record.Postal.Code,
		AccuracyRadius: record.Location.AccuracyRadius,
	}, nil
}

// GetAnonymousInfo retrieves anonymous IP information for the given IP address.
func (s Service) GetAnonymousInfo(ip string) (*domain.AnonymousInfo, error) {
	ipAddress, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("[GeoService:GetAnonymousInfo][err: %w]", err)
	}

	record, err := s.dbAnonymous.AnonymousIP(ipAddress)
	if err != nil {
		return nil, fmt.Errorf("[GeoService:GetAnonymousInfo][err: %w]", err)
	}

	return &domain.AnonymousInfo{
		IsAnonymous:        record.IsAnonymous,
		IsAnonymousVPN:     record.IsAnonymousVPN,
		IsHostingProvider:  record.IsHostingProvider,
		IsPublicProxy:      record.IsPublicProxy,
		IsResidentialProxy: record.IsResidentialProxy,
		IsTorExitNode:      record.IsTorExitNode,
		Network:            record.Network.String(),
	}, nil
}
