package networkEntities

import (
	"domain_threat_intelligence_api/cmd/core/entities/ossEntities"
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

	// community scoring
	CommunityScores []communityScore `json:"CommunityScores"`

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

type scanIntValue struct {
	Value      *uint8         `json:"Value"`
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

			p.addIdentityValues("", "", "", body.Org, body.Region, body.Country, source, now)

		case SCAN_TYPE_OSS_VT_IP:
			source = PROVIDER_SOURCE_VIRUS_TOTAL

			var body ossEntities.VTIPScanBody
			err = s.Data.Scan(&body)

			p.addIdentityValues(strconv.Itoa(body.Data.Attributes.ASN), "", body.Data.Attributes.JARM, body.Data.Attributes.ASOwner, body.Data.Attributes.RegionalInternetRegistry, body.Data.Attributes.Country, source, now)
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

			p.addIdentityValues("", "", body.Data.Attributes.JARM, "", "", "", source, now)
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

func (p *NetworkNodeProfile) addIdentityValues(asn, isp, jarm, org, region, country string, source providerSource, timestamp time.Time) {
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
		Value:      score,
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

type providerSource string

const (
	PROVIDER_SOURCE_IP_INFO     providerSource = "IPInfo"
	PROVIDER_SOURCE_VIRUS_TOTAL                = "VirusTotal"
)
