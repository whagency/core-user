package controllers

import (
	"fmt"

	"user-service/internal/domain"
)

type GeoCtrl struct {
	geoService domain.GeoService
}

func NewGeoController(
	geoService domain.GeoService,
) *GeoCtrl {
	return &GeoCtrl{
		geoService: geoService,
	}
}

// GetGeoInfo provides receiving geo data such as city name, country, time zone, latitude, longitude, etc.
func (c *GeoCtrl) GetGeoInfo(ip string) (*domain.GeoInfo, error) {
	geoData, err := c.geoService.GetGeoInfo(ip)
	if err != nil {
		return nil, fmt.Errorf("[GeoCtrl:GetGeoInfo]%w", err)
	}

	return geoData, nil
}

// GetAnonymousInfo provides receiving VPN anonymous data such as is ip used proxy, is used VPN, is a hosting address etc.
func (c *GeoCtrl) GetAnonymousInfo(ip string) (*domain.AnonymousInfo, error) {
	geoData, err := c.geoService.GetAnonymousInfo(ip)
	if err != nil {
		return nil, fmt.Errorf("[GeoCtrl:GetAnonymousInfo]%w", err)
	}

	return geoData, nil
}
