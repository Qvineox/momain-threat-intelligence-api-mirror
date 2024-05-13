package networkEntities

import (
	"github.com/jackc/pgtype"
	"slices"
	"strings"
	"time"
)

var CommonTLDs = []string{"ru", "com"}

// NetworkNodeCard represents compacted data about network node. Used heavily in WebUI for quick data representation.
type NetworkNodeCard struct {
	NodeUUID pgtype.UUID `json:"UUID"`
	Identity string      `json:"Identity"`
	TypeID   uint64      `json:"NodeTypeId"`

	// CountryFlagCode uses Alpha-2 (ISO 3166-1-alpha-2) country codes to query country flags in WebUI
	// https://flagicons.lipis.dev/ UI library is used
	CountryFlagCodes []string `json:"CountryFlagCodes"` // https://www.iban.com/country-codes
	CountryNames     []string `json:"CountryNames"`

	Scoring *NetworkNodeScoring   `json:"Scoring"`
	Alerts  NetworkNodeCardAlerts `json:"Alerts"`

	DiscoveredAt *time.Time `json:"DiscoveredAt"`
	CreatedAt    *time.Time `json:"CreatedAt"`
	UpdatedAt    *time.Time `json:"UpdatedAt"`
}

type NetworkNodeCardAlerts struct {
	High []NetworkNodeAlert `json:"High"`
	Mid  []NetworkNodeAlert `json:"Mid"`
	Low  []NetworkNodeAlert `json:"Low"`
}

// NewNetworkNodeCardFromProfile creates NetworkNodeCard with alerts
func NewNetworkNodeCardFromProfile(profile *NetworkNodeProfile) *NetworkNodeCard {
	codes, names := getCountryNameCode(profile.Country)

	card := &NetworkNodeCard{
		NodeUUID:         profile.NodeUUID,
		Identity:         profile.Identity,
		TypeID:           profile.NodeTypeID,
		CountryFlagCodes: codes,
		CountryNames:     names,
		Scoring:          profile.Scoring,
		Alerts:           generateAlerts(profile),
		DiscoveredAt:     profile.DiscoveredAt,
		CreatedAt:        profile.CreatedAt,
		UpdatedAt:        profile.UpdatedAt,
	}

	return card
}

func generateAlerts(profile *NetworkNodeProfile) (alerts NetworkNodeCardAlerts) {
	// identity provider
	{
		if hasBoolScanValue(profile.IsGeneric, true) || hasBoolScanValue(profile.IsCommon, true) {
			alerts.Low = append(alerts.Low, ALERT_LOW_GENERIC)
		}
	}

	// geography checks
	{
		if len(profile.Country) > 0 {
			hasAllowedCountryCode := slices.ContainsFunc(profile.Country, func(v1 scanStringValue) bool {
				return slices.ContainsFunc(allowedCountryCodes, func(v2 string) bool {
					return v1.Value == v2
				})
			})

			hasDisallowedCountryCode := slices.ContainsFunc(profile.Country, func(v1 scanStringValue) bool {
				return slices.ContainsFunc(disallowedCountryCodes, func(v2 string) bool {
					return v1.Value == v2
				})
			})

			if hasDisallowedCountryCode {
				alerts.Mid = append(alerts.Low, ALERT_MID_GEO)
			} else if !hasAllowedCountryCode {
				alerts.Low = append(alerts.Low, ALERT_LOW_GEO)
			}
		} else {
			alerts.Low = append(alerts.Low, ALERT_LOW_NO_DATA)
		}
	}

	// privacy
	{
		if hasBoolScanValue(profile.IsVPN, true) || hasBoolScanValue(profile.IsProxy, true) {
			alerts.Mid = append(alerts.Mid, ALERT_MID_PRIVACY)
		}

		if hasBoolScanValue(profile.IsHosting, true) {
			alerts.Low = append(alerts.Low, ALERT_LOW_HOSTING)
		}
	}

	// malicious activity
	{
		if hasBoolScanValue(profile.IsSPAM, true) {
			alerts.Mid = append(alerts.Mid, ALERT_MID_SPAM)
		}

		if hasBoolScanValue(profile.IsPhishing, true) {
			alerts.High = append(alerts.High, ALERT_HIGH_PHISHING)
		}

		if hasBoolScanValue(profile.IsMalwareDistributor, true) {
			alerts.High = append(alerts.High, ALERT_HIGH_MALWARE)
		}

		if hasBoolScanValue(profile.IsDarkWeb, true) {
			alerts.Low = append(alerts.Low, ALERT_LOW_DARK_WEB)
		}
	}

	// blacklists
	{
		if profile.IsBlacklisted {
			alerts.Mid = append(alerts.Mid, ALERT_MID_BLACKLISTED)
		}

		if len(profile.ExternalBlacklists) > 0 {
			alerts.High = append(alerts.High, ALERT_HIGH_BLACKLISTED)
		}
	}

	// scoring
	{
		if profile.Scoring == nil {
			alerts.Low = append(alerts.Low, ALERT_LOW_NO_SCORING)
		} else {
			if *profile.Scoring.DGAScore >= 0.6 {
				alerts.High = append(alerts.High, ALERT_HIGH_DGA)
			}

			if *profile.Scoring.SemanticScore >= 0.6 {
				alerts.Mid = append(alerts.Mid, ALERT_MID_SEMANTIC)
			}

			if *profile.Scoring.FinalScore >= 0.6 {
				alerts.High = append(alerts.High, ALERT_HIGH_SCORING)
			}
		}
	}

	// miscellaneous
	if profile.NodeTypeID == NETWORK_NODE_TYPE_DOMAIN {
		parts := strings.Split(profile.Identity, ".")
		if len(parts) > 1 {
			tld := parts[len(parts)-1]

			hasAllowedTLD := slices.ContainsFunc(allowedTLDs, func(v string) bool {
				return tld == v
			})

			if !hasAllowedTLD {
				alerts.Low = append(alerts.Low, ALERT_LOW_TLD)
			}
		}
	}

	return alerts
}

func getCountryNameCode(tags []scanStringValue) (names, codes []string) {
	var countries []string

	for _, v := range tags {
		countries = append(countries, v.Value)
	}

	countries = slices.Compact(countries)

	return countries, []string{"xx"}
}

func hasBoolScanValue(tags []scanBoolValue, value bool) bool {
	i := slices.IndexFunc(tags, func(v scanBoolValue) bool {
		return v.Value == value
	})

	return i != -1
}

var allowedTLDs = []string{"ru", "com"}
var allowedCountryCodes = []string{"ru", "russia"}
var disallowedCountryCodes = []string{"su", "ua"}
