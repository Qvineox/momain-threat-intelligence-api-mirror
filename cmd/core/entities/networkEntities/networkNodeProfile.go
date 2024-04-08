package networkEntities

import (
	"domain_threat_intelligence_api/cmd/core/entities/ossEntities"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"
)

// NetworkNodeProfile represents single compiled report about network node
type NetworkNodeProfile struct {
	// owner identity data
	ASNs          []scanStringValue `json:"ASNs"`
	ISPs          []scanStringValue `json:"ISPs"`
	JARMs         []scanStringValue `json:"JARMs"`
	Organisations []scanStringValue `json:"Organisations"`

	// tagging and clusterization
	Categories []scanStringValue `json:"Categories"`
	Tags       []scanStringValue `json:"Tags"`

	// geographical data
	Regions   []scanStringValue `json:"Regions"`
	Countries []scanStringValue `json:"Countries"`
	Cities    []scanStringValue `json:"Cities"`
	Longitude float64           `json:"Longitude"`
	Latitude  float64           `json:"Latitude"`

	// domain data
	IsDNSValid     []scanBoolValue   `json:"IsDNSValid"`
	Registrar      []scanStringValue `json:"Registrar"`
	DomainRank     []scanIntValue    `json:"DomainRank"`
	DomainAge      []scanTimeValue   `json:"DomainAge"`
	IsDomainParked []scanBoolValue   `json:"IsDomainParked"`

	// blacklists data
	IsBlacklisted      bool                `json:"IsBlacklisted"`      // IsBlacklisted for internal blacklisting
	ExternalBlacklists []externalBlacklist `json:"ExternalBlacklists"` // ExternalBlacklists from external blacklists (i.e. VirusTotal)

	// external scoring
	ProviderScores []scanIntValue `json:"ProviderScores"`

	// internal scoring (ml analytics)
	DGAScore              float32    `json:"DGAScore"`
	SemanticScore         float32    `json:"SemanticScore"`
	DNSScore              float32    `json:"DNSScore"`
	OverallScore          float32    `json:"OverallScore"`
	IsMalicious           bool       `json:"IsMalicious"`
	LatestScoreEvaluation *time.Time `json:"LatestScoreEvaluation"`

	// anonymity tools usage
	IsVPN   []scanBoolValue `json:"IsVPN"`
	IsProxy []scanBoolValue `json:"IsProxy"`
	IsTOR   []scanBoolValue `json:"IsTOR"`

	// mailing system
	IsMailValid  []scanBoolValue `json:"IsMailValid"`
	IsHoneypot   []scanBoolValue `json:"IsHoneypot"`
	IsDisposable []scanBoolValue `json:"IsDisposable"`
	CanDeliverTo []scanBoolValue `json:"CanDeliverTo"`
	IsCommon     []scanBoolValue `json:"IsCommon"`
	IsGeneric    []scanBoolValue `json:"IsGeneric"`
	IsCatchAll   []scanBoolValue `json:"IsCatchAll"`

	// malicious activity
	IsSPAM               []scanBoolValue `json:"IsSPAM"`
	IsPhishing           []scanBoolValue `json:"IsPhishing"`
	IsMalwareDistributor []scanBoolValue `json:"IsMalwareDistributor"`
	IsCrawler            []scanBoolValue `json:"IsCrawler"`
	// RecentMaliciousActivity []scanBoolValue `json:"RecentMaliciousActivity"`

	// abuse and leaks
	RecentLeaks []scanBoolValue   `json:"RecentLeaks"`
	Alerts      []scanStringValue `json:"Alerts"`

	// content warnings
	IsNSFW []scanBoolValue `json:"IsNSFW"`

	// community scoring
	CommunityScores []communityScore `json:"CommunityScores"`

	// host data
	OpenPorts map[uint64]portData `json:"OpenPorts"`

	// latest scanning data
	LatestScans []latestScan `json:"LatestScans"`
}

type latestScan struct {
	Source     providerSource `json:"Source"`
	TypeID     ScanType       `json:"TypeID"`
	AssignedAt time.Time      `json:"AssignedAt"`
}

type scanStringValue struct {
	Value      string         `json:"Value"`
	Source     providerSource `json:"Source"`
	AssignedAt time.Time      `json:"AssignedAt"`
}

type scanBoolValue struct {
	Value      bool           `json:"Value"`
	Source     providerSource `json:"Source"`
	AssignedAt time.Time      `json:"AssignedAt"`
}

type scanIntValue struct {
	Value      int            `json:"Value"`
	Source     providerSource `json:"Source"`
	AssignedAt time.Time      `json:"AssignedAt"`
}

type scanTimeValue struct {
	Value      time.Time      `json:"Value"`
	Source     providerSource `json:"Source"`
	AssignedAt time.Time      `json:"AssignedAt"`
}

type externalBlacklist struct {
	Name         string    `json:"Name"`
	Tag          string    `json:"Tag"`
	DiscoveredAt time.Time `json:"DiscoveredAt"`
}

type communityScore struct {
	PositiveScores uint64         `json:"Positive"`
	NegativeScores uint64         `json:"Negative"`
	Source         providerSource `json:"Source"`
	AssignedAt     time.Time      `json:"AssignedAt"`
}

type portData struct {
	Banner       string         `json:"Banner"`
	Data         string         `json:"Data"`
	Source       providerSource `json:"Source"`
	DiscoveredAt time.Time      `json:"DiscoveredAt"`
}

func NewNetworkNodeProfile() *NetworkNodeProfile {
	return &NetworkNodeProfile{}
}

func (p *NetworkNodeProfile) WithBlacklisted(isBlacklisted bool) *NetworkNodeProfile {
	p.IsBlacklisted = isBlacklisted
	return p
}

func (p *NetworkNodeProfile) WithNodeScans(scans []NetworkNodeScan) *NetworkNodeProfile {
	now := time.Now()

	var source providerSource

	for _, s := range scans {
		var err error

		switch ScanType(s.ScanTypeID) {
		case SCAN_TYPE_OSS_INFO_IP:
			source = PROVIDER_SOURCE_IP_INFO

			var body ossEntities.IPInfoIPScanBody
			err = s.Data.Scan(&body)

			p.addIdentityValues("", "", "", body.Org, source, now)
			p.addGeographicalValues(body.Region, body.Country, body.City, 0, 0, source, now)

		case SCAN_TYPE_OSS_VT_IP:
			source = PROVIDER_SOURCE_VIRUS_TOTAL

			var body ossEntities.VTIPScanBody
			err = s.Data.Scan(&body)

			p.addIdentityValues(strconv.Itoa(body.Data.Attributes.ASN), "", body.Data.Attributes.JARM, body.Data.Attributes.ASOwner, source, now)
			p.addGeographicalValues(body.Data.Attributes.RegionalInternetRegistry, body.Data.Attributes.Country, "", 0, 0, source, now)
			p.addProviderScoring(body.GetRiskScore(), source, now)

			for k, v := range body.Data.Attributes.LastAnalysisResults {
				if slices.Contains([]string{"malicious", "malware"}, v.Result) {
					p.addExternalBlacklist(k, v.Category, now)
				}
			}

		case SCAN_TYPE_OSS_VT_DOMAIN:
			source = PROVIDER_SOURCE_VIRUS_TOTAL

			var body ossEntities.VTDomainScanBody
			err = s.Data.Scan(&body)

			data := body.Data.Attributes

			p.addIdentityValues("", "", data.JARM, "", source, now)
			p.addProviderScoring(body.GetRiskScore(), source, now)
			p.addDomainData(data.Registrar, 0, time.Time{}, false, false, source, now)

			for _, v := range body.Data.Attributes.Categories {
				p.addCategory(v, source, now)
			}

			for _, v := range body.Data.Attributes.Tags {
				p.addTag(v, source, now)
			}

			for k, v := range body.Data.Attributes.LastAnalysisResults {
				if slices.Contains([]string{"malicious", "malware"}, v.Result) {
					p.addExternalBlacklist(k, v.Category, now)
				}
			}

		case SCAN_TYPE_OSS_VT_URL:
			source = PROVIDER_SOURCE_VIRUS_TOTAL

			var body ossEntities.VTURLScanBody
			err = s.Data.Scan(&body)

			p.addProviderScoring(body.GetRiskScore(), source, now)

			for _, v := range body.Data.Attributes.Categories {
				p.addCategory(v, source, now)
			}

			for _, v := range body.Data.Attributes.Tags {
				p.addTag(v, source, now)
			}

			for k, v := range body.Data.Attributes.LastAnalysisResults {
				if slices.Contains([]string{"malicious", "malware"}, v.Result) {
					p.addExternalBlacklist(k, v.Category, now)
				}
			}

			break
		case SCAN_TYPE_OSS_IPQS_IP:
			source = PROVIDER_SOURCE_IP_QUALITY_SCORE

			var body ossEntities.IPQSPrivacyScanBody
			err = s.Data.Scan(&body)

			p.addProviderScoring(body.GetRiskScore(), source, now)
			p.addIdentityValues(strconv.Itoa(body.ASN), body.ISP, "", body.Organization, source, now)
			p.addGeographicalValues(body.Region, body.CountryCode, body.City, body.Longitude, body.Latitude, source, now)
			p.addAnonymityToolValues(body.Vpn, body.Proxy, body.Tor, source, now)

			break
		case SCAN_TYPE_OSS_IPQS_URL, SCAN_TYPE_OSS_IPQS_DOMAIN:
			source = PROVIDER_SOURCE_IP_QUALITY_SCORE

			var body ossEntities.IPQSMaliciousURLScanBody
			err = s.Data.Scan(&body)

			p.addProviderScoring(body.GetRiskScore(), source, now)
			p.addGeographicalValues("", body.CountryCode, "", 0, 0, source, now)
			p.addDomainData("", body.DomainRank, body.DomainAge.Iso, body.Parking, body.DnsValid, source, now)
			p.addCategory(body.Category, source, now)

			break
		case SCAN_TYPE_OSS_IPQS_EMAIL:
			source = PROVIDER_SOURCE_IP_QUALITY_SCORE

			var body ossEntities.IPQSEMailScanBody
			err = s.Data.Scan(&body)

			p.addProviderScoring(body.GetRiskScore(), source, now)

			var canDeliver = false
			if body.Deliverability != "low" {
				canDeliver = true
			}

			p.addMailingValues(body.Valid, body.Disposable, canDeliver, body.Common, body.Generic, body.CatchAll, source, now)
			p.addDomainData("", 0, body.DomainAge.Iso, false, body.DnsValid, source, now)

			break
		case SCAN_TYPE_OSS_SHODAN_IP:
			source = PROVIDER_SOURCE_SHODAN

			var body ossEntities.ShodanHostScanBody
			err = s.Data.Scan(&body)

			p.addGeographicalValues(body.RegionCode, body.CountryName, body.City, body.Longitude, body.Latitude, source, now)
			p.addIdentityValues(body.Asn, body.Isp, "", body.Org, source, now)

			for _, port := range body.Ports {
				p.addPortValue(uint64(port), "", "", source, now)
			}

			for _, v := range body.Tags {
				p.addTag(v, source, now)
			}

			break
		case SCAN_TYPE_OSS_CS_IP:
			source = PROVIDER_SOURCE_CROWDSEC

			var body ossEntities.CrowdSecIPScanBody
			err = s.Data.Scan(&body)

			p.addGeographicalValues("", body.Location.Country, body.Location.City, body.Location.Longitude, body.Location.Latitude, source, now)
			p.addIdentityValues(strconv.Itoa(body.AsNum), "", "", "", source, now)

			for _, c := range body.Classifications.Classifications {
				p.addCategory(fmt.Sprintf("%s (%s)", c.Label, c.Description), source, now)
			}

			p.addProviderScoring(body.GetRiskScore(), source, now)

			break
		case SCAN_TYPE_OSS_CRIM_IP:
			source = PROVIDER_SOURCE_CRIMINAL_IP

			var body ossEntities.CriminalIPIPScanBody
			err = s.Data.Scan(&body)

			// todo: continue

			// p.addGeographicalValues("", body., body.Location.City, body.Location.Longitude, body.Location.Latitude, source, now)
			// p.addIdentityValues(strconv.Itoa(body.AsNum), "", "", "", source, now)
			//
			// for _, c := range body.Classifications.Classifications {
			// 	p.addCategory(fmt.Sprintf("%s (%s)", c.Label, c.Description), source, now)
			// }
			//
			// p.addProviderScoring(body.GetRiskScore(), source, now)

			break
		default:
			slog.Warn("unsupported scan body with ID: ", s.ID)
			break
		}

		if err != nil {
			slog.Error("failed to parse scan body with ID: ", s.ID)
			break
		}

		p.addLatestScan(source, ScanType(s.ScanTypeID), now)
	}

	return p
}

func (p *NetworkNodeProfile) addIdentityValues(asn, isp, jarm, org string, source providerSource, timestamp time.Time) {
	if len(asn) > 0 {
		p.ASNs = append(p.ASNs, scanStringValue{
			Value:      asn,
			Source:     source,
			AssignedAt: timestamp,
		})
	}

	if len(isp) > 0 {
		p.ISPs = append(p.ISPs, scanStringValue{
			Value:      isp,
			Source:     source,
			AssignedAt: timestamp,
		})
	}

	if len(jarm) > 0 {
		p.JARMs = append(p.JARMs, scanStringValue{
			Value:      jarm,
			Source:     source,
			AssignedAt: timestamp,
		})
	}

	if len(org) > 0 {
		p.Organisations = append(p.Organisations, scanStringValue{
			Value:      org,
			Source:     source,
			AssignedAt: timestamp,
		})
	}
}

func (p *NetworkNodeProfile) addDomainData(registrar string, rank int, age time.Time, isValid, isParking bool, source providerSource, timestamp time.Time) {
	if len(registrar) > 0 {
		p.Registrar = append(p.Registrar, scanStringValue{
			Value:      registrar,
			Source:     source,
			AssignedAt: timestamp,
		})
	}

	if rank > 0 {
		p.DomainRank = append(p.DomainRank, scanIntValue{
			Value:      rank,
			Source:     source,
			AssignedAt: timestamp,
		})
	}

	if !age.IsZero() {
		p.DomainAge = append(p.DomainAge, scanTimeValue{
			Value:      age,
			Source:     source,
			AssignedAt: timestamp,
		})
	}

	p.IsDNSValid = append(p.IsDNSValid, scanBoolValue{
		Value:      isValid,
		Source:     source,
		AssignedAt: timestamp,
	})

	if isParking {
		p.IsDomainParked = append(p.IsDomainParked, scanBoolValue{
			Value:      isParking,
			Source:     source,
			AssignedAt: timestamp,
		})
	}
}

func (p *NetworkNodeProfile) addGeographicalValues(region, country, city string, longitude, latitude float64, source providerSource, timestamp time.Time) {
	if len(region) > 0 {
		p.Regions = append(p.Regions, scanStringValue{
			Value:      region,
			Source:     source,
			AssignedAt: timestamp,
		})
	}

	if len(country) > 0 {
		p.Countries = append(p.Countries, scanStringValue{
			Value:      country,
			Source:     source,
			AssignedAt: timestamp,
		})
	}

	if len(city) > 0 {
		p.Countries = append(p.Countries, scanStringValue{
			Value:      country,
			Source:     source,
			AssignedAt: timestamp,
		})
	}

	if longitude > 0 {
		p.Longitude = longitude
	}

	if latitude > 0 {
		p.Latitude = latitude
	}
}

func (p *NetworkNodeProfile) addAnonymityToolValues(isVPN, isProxy, isTOR bool, source providerSource, timestamp time.Time) {
	p.IsVPN = append(p.IsVPN, scanBoolValue{
		Value:      isVPN,
		Source:     source,
		AssignedAt: timestamp,
	})

	p.IsProxy = append(p.IsProxy, scanBoolValue{
		Value:      isProxy,
		Source:     source,
		AssignedAt: timestamp,
	})

	p.IsTOR = append(p.IsTOR, scanBoolValue{
		Value:      isTOR,
		Source:     source,
		AssignedAt: timestamp,
	})
}

func (p *NetworkNodeProfile) addMailingValues(isValid, isDisposable, canDeliverTo, isCommon, isGeneric, isCatchAll bool, source providerSource, timestamp time.Time) {
	p.IsMailValid = append(p.IsMailValid, scanBoolValue{
		Value:      isValid,
		Source:     source,
		AssignedAt: timestamp,
	})

	p.IsDisposable = append(p.IsDisposable, scanBoolValue{
		Value:      isDisposable,
		Source:     source,
		AssignedAt: timestamp,
	})

	p.CanDeliverTo = append(p.CanDeliverTo, scanBoolValue{
		Value:      canDeliverTo,
		Source:     source,
		AssignedAt: timestamp,
	})

	p.IsCommon = append(p.IsCommon, scanBoolValue{
		Value:      isCommon,
		Source:     source,
		AssignedAt: timestamp,
	})

	p.IsCommon = append(p.IsCommon, scanBoolValue{
		Value:      isCommon,
		Source:     source,
		AssignedAt: timestamp,
	})

	p.IsGeneric = append(p.IsGeneric, scanBoolValue{
		Value:      isGeneric,
		Source:     source,
		AssignedAt: timestamp,
	})

	p.IsCatchAll = append(p.IsCatchAll, scanBoolValue{
		Value:      isCatchAll,
		Source:     source,
		AssignedAt: timestamp,
	})
}

func (p *NetworkNodeProfile) addMaliciousActivityValues(spam, phishing, malware, crawler bool, source providerSource, timestamp time.Time) {
	p.IsSPAM = append(p.IsSPAM, scanBoolValue{
		Value:      spam,
		Source:     source,
		AssignedAt: timestamp,
	})

	p.IsPhishing = append(p.IsPhishing, scanBoolValue{
		Value:      phishing,
		Source:     source,
		AssignedAt: timestamp,
	})

	p.IsMalwareDistributor = append(p.IsMalwareDistributor, scanBoolValue{
		Value:      malware,
		Source:     source,
		AssignedAt: timestamp,
	})

	p.IsCrawler = append(p.IsCrawler, scanBoolValue{
		Value:      crawler,
		Source:     source,
		AssignedAt: timestamp,
	})
}

func (p *NetworkNodeProfile) addLatestScan(source providerSource, typeID ScanType, timestamp time.Time) {
	p.LatestScans = append(p.LatestScans, latestScan{
		Source:     source,
		TypeID:     typeID,
		AssignedAt: timestamp,
	})
}

func (p *NetworkNodeProfile) addExternalBlacklist(blacklistName, tag string, timestamp time.Time) {
	p.ExternalBlacklists = append(p.ExternalBlacklists, externalBlacklist{
		Name:         blacklistName,
		Tag:          tag,
		DiscoveredAt: timestamp,
	})
}

func (p *NetworkNodeProfile) addAnalyticsScoring(dga, semantics, dns, overall float32, isMalicious bool, timestamp *time.Time) {
	p.DGAScore = dga
	p.SemanticScore = semantics
	p.DNSScore = dns
	p.OverallScore = overall

	p.IsMalicious = isMalicious

	p.LatestScoreEvaluation = timestamp
}

func (p *NetworkNodeProfile) addProviderScoring(score *uint8, source providerSource, timestamp time.Time) {
	p.ProviderScores = append(p.ProviderScores, scanIntValue{
		Value:      int(*score),
		Source:     source,
		AssignedAt: timestamp,
	})
}

func (p *NetworkNodeProfile) addCategory(category string, source providerSource, timestamp time.Time) {
	p.Categories = append(p.Categories, scanStringValue{
		Value:      category,
		Source:     source,
		AssignedAt: timestamp,
	})
}

func (p *NetworkNodeProfile) addAlert(alert string, source providerSource, timestamp time.Time) {
	p.Alerts = append(p.Alerts, scanStringValue{
		Value:      alert,
		Source:     source,
		AssignedAt: timestamp,
	})
}

func (p *NetworkNodeProfile) addTag(tag string, source providerSource, timestamp time.Time) {
	p.Tags = append(p.Tags, scanStringValue{
		Value:      tag,
		Source:     source,
		AssignedAt: timestamp,
	})
}

func (p *NetworkNodeProfile) addCommunityScore(positive, negative uint64, source providerSource, timestamp time.Time) {
	p.CommunityScores = append(p.CommunityScores, communityScore{
		PositiveScores: positive,
		NegativeScores: negative,
		Source:         source,
		AssignedAt:     timestamp,
	})
}

func (p *NetworkNodeProfile) addPortValue(port uint64, banner, data string, source providerSource, timestamp time.Time) {
	p.OpenPorts[port] = portData{
		Banner:       banner,
		Data:         data,
		Source:       source,
		DiscoveredAt: timestamp,
	}
}

type providerSource string

const (
	PROVIDER_SOURCE_IP_INFO          providerSource = "IPInfo"
	PROVIDER_SOURCE_VIRUS_TOTAL                     = "VirusTotal"
	PROVIDER_SOURCE_IP_QUALITY_SCORE                = "IPQualityScore"
	PROVIDER_SOURCE_SHODAN                          = "Shodan"
	PROVIDER_SOURCE_CROWDSEC                        = "CrowdSec"
	PROVIDER_SOURCE_IP_WHOIS                        = "IPWhoIS"
	PROVIDER_SOURCE_CRIMINAL_IP                     = "CriminalIP"
)
