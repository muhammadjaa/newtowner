package util

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

// GeoLocation holds the relevant geolocation data for an IP address.
// We are primarily interested in Country and the most specific subdivision (City/Region).
// The MaxMind DB provides a hierarchical structure; we'll try to get the most specific name.
type GeoLocation struct {
	CountryCode   string // ISO 3166-1 alpha-2 country code
	CountryName   string
	RegionName    string // Most specific subdivision name (e.g., state, city)
	Latitude      float64
	Longitude     float64
	ContinentCode string
}

var db *maxminddb.Reader // Global variable to hold the opened DB reader

// InitGeoLiteDB opens the MaxMind GeoLite2 database file.
// It should be called once during application startup.
func InitGeoLiteDB(dbPath string) error {
	var err error
	db, err = maxminddb.Open(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open MaxMind DB at %s: %w", dbPath, err)
	}
	return nil
}

// CloseGeoLiteDB closes the MaxMind database. Should be deferred after InitGeoLiteDB.
func CloseGeoLiteDB() {
	if db != nil {
		db.Close()
	}
}

// GetGeoLocationForIP looks up an IP address in the MaxMind database and returns its geolocation.
func GetGeoLocationForIP(ipAddress net.IP) (*GeoLocation, error) {
	if db == nil {
		return nil, fmt.Errorf("MaxMind DB is not initialized. Call InitGeoLiteDB first")
	}

	// Define a struct that matches the GeoLite2-City database schema for the fields we need.
	// You can find the full schema by inspecting the DB or its documentation.
	var record struct {
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		Country struct {
			ISOCode string            `maxminddb:"iso_code"`
			Names   map[string]string `maxminddb:"names"`
		} `maxminddb:"country"`
		Continent struct {
			Code string `maxminddb:"code"`
		} `maxminddb:"continent"`
		Location struct {
			Latitude  float64 `maxminddb:"latitude"`
			Longitude float64 `maxminddb:"longitude"`
		} `maxminddb:"location"`
		Subdivisions []struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"subdivisions"`
	}

	err := db.Lookup(ipAddress, &record)
	if err != nil {
		return nil, fmt.Errorf("error looking up IP %s in MaxMind DB: %w", ipAddress.String(), err)
	}

	geoLoc := &GeoLocation{
		CountryCode:   record.Country.ISOCode,
		CountryName:   record.Country.Names["en"], // Default to English name
		Latitude:      record.Location.Latitude,
		Longitude:     record.Location.Longitude,
		ContinentCode: record.Continent.Code,
	}

	// Get the most specific region name available (City > Subdivision)
	if cityName, ok := record.City.Names["en"]; ok && cityName != "" {
		geoLoc.RegionName = cityName
	} else if len(record.Subdivisions) > 0 {
		if subdivisionName, ok := record.Subdivisions[0].Names["en"]; ok && subdivisionName != "" {
			geoLoc.RegionName = subdivisionName // Use the first (often most general) subdivision if city is not available
		}
	}
	// If country name is empty but code is present (should be rare), use code.
	if geoLoc.CountryName == "" && geoLoc.CountryCode != "" {
		geoLoc.CountryName = geoLoc.CountryCode
	}

	return geoLoc, nil
}

// ResolveHostAndGetGeoLocation resolves a hostname to an IP address (the first one found)
// and then looks up its geolocation.
func ResolveHostAndGetGeoLocation(hostname string) (*GeoLocation, net.IP, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve hostname %s: %w", hostname, err)
	}
	if len(ips) == 0 {
		return nil, nil, fmt.Errorf("no IP addresses found for hostname %s", hostname)
	}

	// Use the first resolved IP address (prefer IPv4 if available, though LookupIP doesn't guarantee order strongly)
	// For simplicity, just take the first one. Could iterate to find a preferred type.
	firstIP := ips[0]

	geoLoc, err := GetGeoLocationForIP(firstIP)
	if err != nil {
		return nil, firstIP, fmt.Errorf("failed to get geolocation for IP %s (from hostname %s): %w", firstIP.String(), hostname, err)
	}

	return geoLoc, firstIP, nil
}

// GetAWSRegionFromGeo attempts to map a geographic location (country code, city/area name)
// to a suitable AWS region. It uses a predefined, simplified mapping.
// `fallbackRegion` is used if no specific mapping is found but the country might have a general default,
// or if geo-lookup itself failed partially.
func GetAWSRegionFromGeo(countryCode, geoAreaName, fallbackRegion string) (string, error) {
	// geoAreaName is typically the city from MaxMind, but can be a state/province.
	// Normalize for caseless comparison
	ccLower := strings.ToLower(countryCode)
	areaLower := strings.ToLower(geoAreaName)

	// This mapping needs to be significantly expanded and refined for production use.
	// Consider factors like major AWS presence, common regional choices, latency, data sovereignty, etc.
	// The order can matter if a geoAreaName might ambiguously map within a country.

	// North America
	if ccLower == "us" { // United States
		if strings.Contains(areaLower, "ashburn") || strings.Contains(areaLower, "virginia") || strings.Contains(areaLower, "washington d.c.") || strings.Contains(areaLower, "dc") {
			return "us-east-1", nil // N. Virginia
		}
		if strings.Contains(areaLower, "ohio") || strings.Contains(areaLower, "columbus") {
			return "us-east-2", nil // Ohio
		}
		if strings.Contains(areaLower, "oregon") || strings.Contains(areaLower, "portland") || strings.Contains(areaLower, "hillsboro") {
			return "us-west-2", nil // Oregon
		}
		if strings.Contains(areaLower, "california") || strings.Contains(areaLower, "los angeles") || strings.Contains(areaLower, "san francisco") || strings.Contains(areaLower, "san jose") || strings.Contains(areaLower, "san diego") {
			return "us-west-1", nil // N. California (covers major CA cities, though us-west-2 might be closer for some northern CA)
		}
		// Add more specific US states/cities or a general US fallback if desired.
		// For now, will rely on global fallback if no specific US match.
	}
	if ccLower == "ca" { // Canada
		if strings.Contains(areaLower, "montreal") || strings.Contains(areaLower, "quebec") {
			return "ca-central-1", nil // Montreal
		}
		if strings.Contains(areaLower, "calgary") || strings.Contains(areaLower, "alberta") {
			return "ca-west-1", nil // Calgary
		}
		if strings.Contains(areaLower, "toronto") || strings.Contains(areaLower, "ontario") { // Toronto often uses ca-central-1
			return "ca-central-1", nil
		}
		if strings.Contains(areaLower, "vancouver") || strings.Contains(areaLower, "british columbia") { // Vancouver might use ca-central-1 or ca-west-1
			return "ca-west-1", nil // Defaulting to Calgary for West
		}
		return "ca-central-1", nil // Default for Canada
	}

	// South America
	if ccLower == "br" { // Brazil
		if strings.Contains(areaLower, "sao paulo") || strings.Contains(areaLower, "são paulo") {
			return "sa-east-1", nil // São Paulo
		}
		return "sa-east-1", nil // Default for Brazil
	}
	// Add other South American countries if needed (e.g., Argentina, Chile often use sa-east-1)

	// Europe
	if ccLower == "gb" || ccLower == "uk" { // United Kingdom
		if strings.Contains(areaLower, "london") {
			return "eu-west-2", nil // London
		}
		if strings.Contains(areaLower, "manchester") { // Manchester might use London or Ireland
			return "eu-west-2", nil
		}
		return "eu-west-2", nil // Default for GB/UK
	}
	if ccLower == "ie" { // Ireland
		if strings.Contains(areaLower, "dublin") {
			return "eu-west-1", nil // Ireland
		}
		return "eu-west-1", nil // Default for Ireland
	}
	if ccLower == "de" { // Germany
		if strings.Contains(areaLower, "frankfurt") {
			return "eu-central-1", nil // Frankfurt
		}
		if strings.Contains(areaLower, "berlin") || strings.Contains(areaLower, "munich") { // Berlin/Munich typically use Frankfurt
			return "eu-central-1", nil
		}
		return "eu-central-1", nil // Default for Germany
	}
	if ccLower == "fr" { // France
		if strings.Contains(areaLower, "paris") {
			return "eu-west-3", nil // Paris
		}
		return "eu-west-3", nil // Default for France
	}
	if ccLower == "se" || ccLower == "sv" { // Sweden (ISO code SE, sometimes SV used locally)
		if strings.Contains(areaLower, "stockholm") {
			return "eu-north-1", nil // Stockholm
		}
		return "eu-north-1", nil // Default for Sweden/Nordics
	}
	if ccLower == "it" { // Italy
		if strings.Contains(areaLower, "milan") {
			return "eu-south-1", nil // Milan
		}
		return "eu-south-1", nil // Default for Italy
	}
	if ccLower == "es" { // Spain
		if strings.Contains(areaLower, "madrid") || strings.Contains(areaLower, "zaragoza") { // Zaragoza is where eu-south-2 is
			return "eu-south-2", nil // Spain Region (Aragon)
		}
		return "eu-south-2", nil // Default for Spain
	}
	if ccLower == "ch" { // Switzerland
		if strings.Contains(areaLower, "zurich") || strings.Contains(areaLower, "zürich") {
			return "eu-central-2", nil // Zurich
		}
		return "eu-central-2", nil // Default for Switzerland
	}
	if ccLower == "pl" { // Poland
		// No direct AWS region in Poland yet, typically Frankfurt or other nearby.
		// Rely on fallback or choose a nearby one if preferred. For now, let fallback handle.
	}
	// Netherlands (NL) often uses Frankfurt (eu-central-1) or Ireland (eu-west-1)
	if ccLower == "nl" {
		if strings.Contains(areaLower, "amsterdam") {
			return "eu-west-1", nil // Amsterdam often closer to Ireland or Frankfurt. Defaulting to Ireland.
		}
		return "eu-west-1", nil
	}

	// Asia Pacific (APAC)
	if ccLower == "au" { // Australia
		if strings.Contains(areaLower, "sydney") || strings.Contains(areaLower, "new south wales") {
			return "ap-southeast-2", nil // Sydney
		}
		if strings.Contains(areaLower, "melbourne") || strings.Contains(areaLower, "victoria") {
			return "ap-southeast-4", nil // Melbourne
		}
		if strings.Contains(areaLower, "perth") || strings.Contains(areaLower, "western australia") { // Perth might use Sydney or Singapore
			return "ap-southeast-2", nil // Defaulting to Sydney for now
		}
		return "ap-southeast-2", nil // Default for AU
	}
	if ccLower == "sg" { // Singapore
		return "ap-southeast-1", nil // Singapore
	}
	if ccLower == "jp" { // Japan
		if strings.Contains(areaLower, "tokyo") {
			return "ap-northeast-1", nil // Tokyo
		}
		if strings.Contains(areaLower, "osaka") {
			return "ap-northeast-3", nil // Osaka
		}
		return "ap-northeast-1", nil // Default for Japan (Tokyo)
	}
	if ccLower == "kr" { // South Korea
		if strings.Contains(areaLower, "seoul") {
			return "ap-northeast-2", nil // Seoul
		}
		return "ap-northeast-2", nil // Default for South Korea
	}
	if ccLower == "in" { // India
		if strings.Contains(areaLower, "mumbai") {
			return "ap-south-1", nil // Mumbai
		}
		if strings.Contains(areaLower, "hyderabad") {
			return "ap-south-2", nil // Hyderabad
		}
		return "ap-south-1", nil // Default for India (Mumbai)
	}
	if ccLower == "id" { // Indonesia
		if strings.Contains(areaLower, "jakarta") {
			return "ap-southeast-3", nil // Jakarta
		}
		return "ap-southeast-3", nil // Default for Indonesia
	}
	if ccLower == "hk" { // Hong Kong SAR
		return "ap-east-1", nil // Hong Kong
	}
	if ccLower == "th" { // Thailand
		// No direct AWS region, typically Singapore
		if strings.Contains(areaLower, "bangkok") {
			return "ap-southeast-1", nil
		}
		return "ap-southeast-1", nil // Default to Singapore for Thailand
	}
	if ccLower == "nz" { // New Zealand
		// No direct AWS region, typically Sydney
		if strings.Contains(areaLower, "auckland") || strings.Contains(areaLower, "wellington") {
			return "ap-southeast-2", nil
		}
		return "ap-southeast-2", nil // Default to Sydney for New Zealand
	}
	if ccLower == "vn" { // Vietnam
		// No direct AWS region, typically Singapore or Hong Kong
		if strings.Contains(areaLower, "ho chi minh city") || strings.Contains(areaLower, "hanoi") {
			return "ap-southeast-1", nil // Default to Singapore
		}
		return "ap-southeast-1", nil
	}
	if ccLower == "my" { // Malaysia
		// No direct AWS region, typically Singapore
		if strings.Contains(areaLower, "kuala lumpur") {
			return "ap-southeast-1", nil
		}
		return "ap-southeast-1", nil
	}
	if ccLower == "ph" { // Philippines
		// No direct AWS region, typically Singapore or Hong Kong
		if strings.Contains(areaLower, "manila") {
			return "ap-southeast-1", nil // Default to Singapore
		}
		return "ap-southeast-1", nil
	}

	// Middle East
	if ccLower == "ae" { // United Arab Emirates
		if strings.Contains(areaLower, "dubai") || strings.Contains(areaLower, "abu dhabi") {
			return "me-central-1", nil // UAE Region
		}
		return "me-central-1", nil // Default for UAE
	}
	if ccLower == "bh" { // Bahrain
		return "me-south-1", nil // Bahrain Region (this is me-south-1)
	}
	if ccLower == "il" { // Israel
		if strings.Contains(areaLower, "tel aviv") {
			return "il-central-1", nil // Tel Aviv
		}
		return "il-central-1", nil // Default for Israel
	}
	// Other Middle Eastern countries (e.g., Saudi Arabia, Qatar) might use UAE or Bahrain, or rely on fallback.

	// Africa
	if ccLower == "za" { // South Africa
		if strings.Contains(areaLower, "cape town") {
			return "af-south-1", nil // Cape Town
		}
		if strings.Contains(areaLower, "johannesburg") { // Johannesburg often uses Cape Town region
			return "af-south-1", nil
		}
		return "af-south-1", nil // Default for South Africa
	}
	// Other African countries might use Cape Town, a European region, or rely on fallback.
	// e.g. Nigeria (NG), Kenya (KE)

	// If no specific mapping found, and a fallbackRegion (e.g., from SDK default) is available and seems plausible
	// (e.g., if geo-lookup failed but we have an SDK default region), use it.
	if fallbackRegion != "" {
		log.Printf("Geo-to-AWS-Region mapping not found for countryCode '%s', geoAreaName '%s'. Using fallback region: %s", countryCode, geoAreaName, fallbackRegion)
		return fallbackRegion, nil
	}

	return "", fmt.Errorf("no suitable AWS region mapping found for countryCode '%s' and area '%s', and no fallback region provided", countryCode, geoAreaName)
}
