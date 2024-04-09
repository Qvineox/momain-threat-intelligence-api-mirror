package networkEntities

import (
	"domain_threat_intelligence_api/cmd/core/entities/ossEntities"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"
)

// NetworkNodeProfile represents single compiled report about network node
type NetworkNodeProfile struct {
	// owner identity data
	ASN          []scanIntValue    `json:"ASN"`
	ISP          []scanStringValue `json:"ISP"`
	JARM         []scanStringValue `json:"JARM"`
	Organisation []scanStringValue `json:"Organisation"`

	// tagging and clusterization
	Category []scanStringValue `json:"Category"`
	Tag      []scanStringValue `json:"Tag"`

	// geographical data
	Region    []scanStringValue `json:"Region"`
	Country   []scanStringValue `json:"Country"`
	City      []scanStringValue `json:"City"`
	Longitude float64           `json:"Longitude"`
	Latitude  float64           `json:"Latitude"`

	// domain data
	IsDNSValid     []scanBoolValue   `json:"IsDNSValid"`
	Registrar      []scanStringValue `json:"Registrar"`
	DomainRank     []scanIntValue    `json:"DomainRank"`
	DomainAge      []scanTimeValue   `json:"DomainAge"`
	IsDomainParked []scanBoolValue   `json:"IsDomainParked"`

	// domain records data
	ARecords     []domainRecordValue `json:"ARecords"`
	AAAARecords  []domainRecordValue `json:"AAAARecords"`
	CNameRecords []domainRecordValue `json:"CNameRecords"`
	MXRecords    []domainRecordValue `json:"MXRecords"`
	NSRecords    []domainRecordValue `json:"NSRecords"`
	PTRRecords   []domainRecordValue `json:"PTRRecords"`
	SOARecords   []domainRecordValue `json:"SOARecords"`

	// blacklists data
	IsBlacklisted      bool                `json:"IsBlacklisted"`      // IsBlacklisted for internal blacklisting
	ExternalBlacklists []externalBlacklist `json:"ExternalBlacklists"` // ExternalBlacklists from external blacklists (i.e. VirusTotal)

	// external scoring
	ProviderScore []scanIntValue `json:"ProviderScore"`

	// internal scoring (ml analytics)
	DGAScore              float32    `json:"DGAScore"`
	SemanticScore         float32    `json:"SemanticScore"`
	DNSScore              float32    `json:"DNSScore"`
	OverallScore          float32    `json:"OverallScore"`
	IsMalicious           bool       `json:"IsMalicious"`
	LatestScoreEvaluation *time.Time `json:"LatestScoreEvaluation"`

	// anonymity tools usage
	IsVPN     []scanBoolValue `json:"IsVPN"`
	IsProxy   []scanBoolValue `json:"IsProxy"`
	IsTOR     []scanBoolValue `json:"IsTOR"`
	IsDarkWeb []scanBoolValue `json:"IsDarkWeb"`
	IsHosting []scanBoolValue `json:"IsHosting"`

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

	// vulnerabilities
	// todo: add vulnerability data from CrowdSec, CriminalIP

	// certificates
	// todo: add certificates data from CrowdSec, CriminalIP

	// latest scanning data
	LatestScans []latestScan `json:"LatestScans"`
}

type latestScan struct {
	CommonScanTag
	TypeID ScanType `json:"TypeID"`
}

type scanStringValue struct {
	CommonScanTag
	Value string `json:"Value"`
}

type scanBoolValue struct {
	CommonScanTag
	Value bool `json:"Value"`
}

type scanIntValue struct {
	CommonScanTag
	Value int `json:"Value"`
}

type scanTimeValue struct {
	CommonScanTag

	Value time.Time `json:"Value"`
}

type externalBlacklist struct {
	CommonScanTag

	Name string `json:"Name"`
	Tag  string `json:"Tag"`
}

type communityScore struct {
	CommonScanTag

	PositiveScores uint64 `json:"Positive"`
	NegativeScores uint64 `json:"Negative"`
}

type portData struct {
	CommonScanTag

	Application string `json:"Application"`
	Protocol    string `json:"Protocol"`
	Banner      string `json:"Banner"`

	// binary data from external sources
	Data interface{} `json:"Data"`
}

type domainRecordValue struct {
	CommonScanTag

	Value string `json:"Value"`
}

type CommonScanTag struct {
	Source    providerSource `json:"Source"`
	Timestamp time.Time      `json:"Timestamp"`
}

func NewNetworkNodeProfile() *NetworkNodeProfile {
	profile := &NetworkNodeProfile{}
	profile.OpenPorts = make(map[uint64]portData)

	return profile
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

		if !s.IsComplete {
			continue
		}

		switch ScanType(s.ScanTypeID) {
		case SCAN_TYPE_OSS_INFO_IP:
			source = PROVIDER_SOURCE_IP_INFO

			var body ossEntities.IPInfoIPScanBody
			err = json.Unmarshal(s.Data, &body)
			if err != nil {
				continue
			}

			p.addIdentityValues(0, "", "", body.Org, source, now)
			p.addGeographicalValues(body.Region, body.Country, body.City, 0, 0, source, now)
		case SCAN_TYPE_OSS_VT_IP:
			source = PROVIDER_SOURCE_VIRUS_TOTAL

			var body ossEntities.VTIPScanBody
			err = json.Unmarshal(s.Data, &body)
			if err != nil {
				continue
			}

			p.addIdentityValues(body.Data.Attributes.ASN, "", body.Data.Attributes.JARM, body.Data.Attributes.ASOwner, source, now)
			p.addGeographicalValues(body.Data.Attributes.RegionalInternetRegistry, body.Data.Attributes.Country, "", 0, 0, source, now)
			p.addProviderScoring(body.GetRiskScore(), source, now)

			for k, v := range body.Data.Attributes.LastAnalysisResults {
				if slices.Contains([]string{"malicious", "malware"}, v.Result) {
					p.addExternalBlacklist(k, v.Category, source, now)
				}
			}
		case SCAN_TYPE_OSS_VT_DOMAIN:
			source = PROVIDER_SOURCE_VIRUS_TOTAL

			var body ossEntities.VTDomainScanBody
			err = json.Unmarshal(s.Data, &body)
			if err != nil {
				continue
			}

			data := body.Data.Attributes

			p.addIdentityValues(0, "", data.JARM, "", source, now)
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
					p.addExternalBlacklist(k, v.Category, source, now)
				}
			}
		case SCAN_TYPE_OSS_VT_URL:
			source = PROVIDER_SOURCE_VIRUS_TOTAL

			var body ossEntities.VTURLScanBody
			err = json.Unmarshal(s.Data, &body)
			if err != nil {
				continue
			}

			p.addProviderScoring(body.GetRiskScore(), source, now)

			for _, v := range body.Data.Attributes.Categories {
				p.addCategory(v, source, now)
			}

			for _, v := range body.Data.Attributes.Tags {
				p.addTag(v, source, now)
			}

			for k, v := range body.Data.Attributes.LastAnalysisResults {
				if slices.Contains([]string{"malicious", "malware"}, v.Result) {
					p.addExternalBlacklist(k, v.Category, source, now)
				}
			}

			break
		case SCAN_TYPE_OSS_IPQS_IP:
			source = PROVIDER_SOURCE_IP_QUALITY_SCORE

			var body ossEntities.IPQSPrivacyScanBody
			err = json.Unmarshal(s.Data, &body)
			if err != nil {
				continue
			}

			p.addProviderScoring(body.GetRiskScore(), source, now)
			p.addIdentityValues(body.ASN, body.ISP, "", body.Organization, source, now)
			p.addGeographicalValues(body.Region, body.CountryCode, body.City, body.Longitude, body.Latitude, source, now)
			p.addAnonymityToolValues(body.Vpn, body.Proxy, body.Tor, source, now)

			break
		case SCAN_TYPE_OSS_IPQS_URL, SCAN_TYPE_OSS_IPQS_DOMAIN:
			source = PROVIDER_SOURCE_IP_QUALITY_SCORE

			var body ossEntities.IPQSMaliciousURLScanBody
			err = json.Unmarshal(s.Data, &body)
			if err != nil {
				continue
			}

			p.addProviderScoring(body.GetRiskScore(), source, now)
			p.addGeographicalValues("", body.CountryCode, "", 0, 0, source, now)
			p.addDomainData("", body.DomainRank, body.DomainAge.Iso, body.Parking, body.DnsValid, source, now)
			p.addCategory(body.Category, source, now)

			break
		case SCAN_TYPE_OSS_IPQS_EMAIL:
			source = PROVIDER_SOURCE_IP_QUALITY_SCORE

			var body ossEntities.IPQSEMailScanBody
			err = json.Unmarshal(s.Data, &body)
			if err != nil {
				continue
			}

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
			err = json.Unmarshal(s.Data, &body)
			if err != nil {
				continue
			}

			p.addGeographicalValues(body.RegionCode, body.CountryName, body.City, body.Longitude, body.Latitude, source, now)

			asn, _ := strconv.Atoi(body.Asn)
			p.addIdentityValues(asn, body.Isp, "", body.Org, source, now)

			for _, port := range body.Ports {
				p.addPortValue(uint64(port), "", "", "", "", source, now)
				// todo: parse shodan port data
			}

			for _, v := range body.Tags {
				p.addTag(v, source, now)
			}

			break
		case SCAN_TYPE_OSS_CS_IP:
			source = PROVIDER_SOURCE_CROWDSEC

			var body ossEntities.CrowdSecIPScanBody
			err = json.Unmarshal(s.Data, &body)
			if err != nil {
				continue
			}

			p.addGeographicalValues("", body.Location.Country, body.Location.City, body.Location.Longitude, body.Location.Latitude, source, now)
			p.addIdentityValues(body.AsNum, "", "", "", source, now)

			for _, c := range body.Classifications.Classifications {
				p.addCategory(fmt.Sprintf("%s (%s)", c.Label, c.Description), source, now)
			}

			p.addProviderScoring(body.GetRiskScore(), source, now)

			break
		case SCAN_TYPE_OSS_CRIM_IP:
			source = PROVIDER_SOURCE_CRIMINAL_IP

			var body ossEntities.CriminalIPIPScanBody
			err = json.Unmarshal(s.Data, &body)
			if err != nil {
				continue
			}

			// todo: add category data

			p.addAnonymityToolValues(body.Issues.IsAnonymousVpn || body.Issues.IsVpn, body.Issues.IsProxy, body.Issues.IsTor, source, now)

			if body.Domain.Count > 0 && len(body.Domain.Data) > 0 {
				// todo: sort by date

				data := body.Domain.Data[0]
				domainCreatedAt, _ := time.Parse("2006-01-02 15:04:05", data.CreateDate)

				p.addDomainData(data.Registrar, 0, domainCreatedAt, true, false, source, now)
			}

			if body.Whois.Count > 0 && len(body.Whois.Data) > 0 {
				// todo: sort by date

				data := body.Whois.Data[0]

				//p.addGeographicalValues(body.RegionCode, body.CountryName, body.City, body.Longitude, body.Latitude, source, now)
				//p.addIdentityValues(body.Asn, body.Isp, "", body.Org, source, now)

				p.addGeographicalValues(data.Region, data.OrgCountryCode, data.City, data.Longitude, data.Latitude, source, now)
				p.addIdentityValues(data.AsNo, "", "", data.OrgName, source, now)
			}

			for _, port := range body.Port.Data {
				p.addPortValue(uint64(port.OpenPortNo), port.Banner, port.AppName, port.Protocol, "", source, now)
			}

			// p.addGeographicalValues("", body., body.Location.City, body.Location.Longitude, body.Location.Latitude, source, now)
			// p.addIdentityValues(strconv.Itoa(body.AsNum), "", "", "", source, now)
			//
			// for _, c := range body.Classifications.Classifications {
			// 	p.addCategory(fmt.Sprintf("%s (%s)", c.Label, c.Description), source, now)
			// }
			//
			// p.addProviderScoring(body.GetRiskScore(), source, now)

			break
		case SCAN_TYPE_OSS_CRIM_DOMAIN:
			source = PROVIDER_SOURCE_CRIMINAL_IP

			var body ossEntities.CriminalIPDomainScanBody
			err = json.Unmarshal(s.Data, &body)
			if err != nil {
				continue
			}

			p.addDomainRecordsValue(
				[]string{}, // todo: add A records
				body.Data.DnsRecord.DnsRecordTypeCname,
				[]string{}, // body.Data.DnsRecord.DnsRecordTypeMx, // todo: check wtf with [][]
				body.Data.DnsRecord.DnsRecordTypeNs,
				body.Data.DnsRecord.DnsRecordTypePtr,
				body.Data.DnsRecord.DnsRecordTypeSoa,
				source,
				now,
			)

			for _, d := range body.Data.Classification.DomainType {
				p.addCategory(d.Type, source, now) // todo: check
			}

			break
		default:
			slog.Warn("unsupported scan body with ID: ", s.ID)
			break
		}

		p.addLatestScan(source, ScanType(s.ScanTypeID), s.CreatedAt)
	}

	return p
}

func (p *NetworkNodeProfile) addIdentityValues(asn int, isp, jarm, org string, source providerSource, timestamp time.Time) {
	if asn > 0 {
		p.ASN = append(p.ASN, scanIntValue{
			CommonScanTag: CommonScanTag{
				Source:    source,
				Timestamp: timestamp,
			},
			Value: asn,
		})
	}

	if len(isp) > 0 {
		p.ISP = append(p.ISP, scanStringValue{
			CommonScanTag: CommonScanTag{
				Source:    source,
				Timestamp: timestamp,
			},
			Value: isp,
		})
	}

	if len(jarm) > 0 {
		p.JARM = append(p.JARM, scanStringValue{
			CommonScanTag: CommonScanTag{
				Source:    source,
				Timestamp: timestamp,
			},
			Value: jarm,
		})
	}

	if len(org) > 0 {
		p.Organisation = append(p.Organisation, scanStringValue{
			CommonScanTag: CommonScanTag{
				Source:    source,
				Timestamp: timestamp,
			},
			Value: org,
		})
	}
}

func (p *NetworkNodeProfile) addDomainData(registrar string, rank int, age time.Time, isValid, isParking bool, source providerSource, timestamp time.Time) {
	if len(registrar) > 0 {
		p.Registrar = append(p.Registrar, scanStringValue{
			CommonScanTag: CommonScanTag{
				Source:    source,
				Timestamp: timestamp,
			},
			Value: registrar,
		})
	}

	if rank > 0 {
		p.DomainRank = append(p.DomainRank, scanIntValue{
			CommonScanTag: CommonScanTag{
				Source:    source,
				Timestamp: timestamp,
			},
			Value: rank,
		})
	}

	if !age.IsZero() {
		p.DomainAge = append(p.DomainAge, scanTimeValue{
			CommonScanTag: CommonScanTag{
				Source:    source,
				Timestamp: timestamp,
			},
			Value: age,
		})
	}

	p.IsDNSValid = append(p.IsDNSValid, scanBoolValue{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: isValid,
	})

	if isParking {
		p.IsDomainParked = append(p.IsDomainParked, scanBoolValue{
			CommonScanTag: CommonScanTag{
				Source:    source,
				Timestamp: timestamp,
			},
			Value: isParking,
		})
	}
}

func (p *NetworkNodeProfile) addGeographicalValues(region, country, city string, longitude, latitude float64, source providerSource, timestamp time.Time) {
	if len(region) > 0 {
		p.Region = append(p.Region, scanStringValue{
			CommonScanTag: CommonScanTag{
				Source:    source,
				Timestamp: timestamp,
			},
			Value: region,
		})
	}

	if len(country) > 0 {
		p.Country = append(p.Country, scanStringValue{
			CommonScanTag: CommonScanTag{
				Source:    source,
				Timestamp: timestamp,
			},
			Value: country,
		})
	}

	if len(city) > 0 {
		p.Country = append(p.Country, scanStringValue{
			CommonScanTag: CommonScanTag{
				Source:    source,
				Timestamp: timestamp,
			},
			Value: country,
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
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: isVPN,
	})

	p.IsProxy = append(p.IsProxy, scanBoolValue{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: isProxy,
	})

	p.IsTOR = append(p.IsTOR, scanBoolValue{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: isTOR,
	})
}

func (p *NetworkNodeProfile) addMailingValues(isValid, isDisposable, canDeliverTo, isCommon, isGeneric, isCatchAll bool, source providerSource, timestamp time.Time) {
	p.IsMailValid = append(p.IsMailValid, scanBoolValue{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: isValid,
	})

	p.IsDisposable = append(p.IsDisposable, scanBoolValue{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: isDisposable,
	})

	p.CanDeliverTo = append(p.CanDeliverTo, scanBoolValue{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: canDeliverTo,
	})

	p.IsCommon = append(p.IsCommon, scanBoolValue{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: isCommon,
	})

	p.IsCommon = append(p.IsCommon, scanBoolValue{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: isCommon,
	})

	p.IsGeneric = append(p.IsGeneric, scanBoolValue{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: isGeneric,
	})

	p.IsCatchAll = append(p.IsCatchAll, scanBoolValue{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: isCatchAll,
	})
}

func (p *NetworkNodeProfile) addMaliciousActivityValues(spam, phishing, malware, crawler bool, source providerSource, timestamp time.Time) {
	p.IsSPAM = append(p.IsSPAM, scanBoolValue{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: spam,
	})

	p.IsPhishing = append(p.IsPhishing, scanBoolValue{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: phishing,
	})

	p.IsMalwareDistributor = append(p.IsMalwareDistributor, scanBoolValue{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: malware,
	})

	p.IsCrawler = append(p.IsCrawler, scanBoolValue{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: crawler,
	})
}

func (p *NetworkNodeProfile) addLatestScan(source providerSource, typeID ScanType, timestamp time.Time) {
	p.LatestScans = append(p.LatestScans, latestScan{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		TypeID: typeID,
	})
}

func (p *NetworkNodeProfile) addExternalBlacklist(blacklistName, tag string, source providerSource, timestamp time.Time) {
	p.ExternalBlacklists = append(p.ExternalBlacklists, externalBlacklist{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Name: blacklistName,
		Tag:  tag,
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
	p.ProviderScore = append(p.ProviderScore, scanIntValue{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: int(*score),
	})
}

func (p *NetworkNodeProfile) addCategory(category string, source providerSource, timestamp time.Time) {
	p.Category = append(p.Category, scanStringValue{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: category,
	})
}

func (p *NetworkNodeProfile) addAlert(alert string, source providerSource, timestamp time.Time) {
	p.Alerts = append(p.Alerts, scanStringValue{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: alert,
	})
}

func (p *NetworkNodeProfile) addTag(tag string, source providerSource, timestamp time.Time) {
	p.Tag = append(p.Tag, scanStringValue{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Value: tag,
	})
}

func (p *NetworkNodeProfile) addCommunityScore(positive, negative uint64, source providerSource, timestamp time.Time) {
	p.CommunityScores = append(p.CommunityScores, communityScore{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		PositiveScores: positive,
		NegativeScores: negative,
	})
}

func (p *NetworkNodeProfile) addPortValue(port uint64, banner, application, protocol, data string, source providerSource, timestamp time.Time) {
	p.OpenPorts[port] = portData{
		CommonScanTag: CommonScanTag{
			Source:    source,
			Timestamp: timestamp,
		},
		Application: application,
		Protocol:    protocol,
		Banner:      banner,
		Data:        data,
	}
}

func (p *NetworkNodeProfile) addDomainRecordsValue(a, cname, mx, ns, ptr, soa []string, source providerSource, timestamp time.Time) {
	for _, r := range a {
		p.ARecords = append(p.ARecords, domainRecordValue{
			CommonScanTag: CommonScanTag{
				Source:    source,
				Timestamp: timestamp,
			},
			Value: r,
		})
	}

	for _, r := range cname {
		p.CNameRecords = append(p.CNameRecords, domainRecordValue{
			CommonScanTag: CommonScanTag{
				Source:    source,
				Timestamp: timestamp,
			},
			Value: r,
		})
	}

	for _, r := range mx {
		p.MXRecords = append(p.MXRecords, domainRecordValue{
			CommonScanTag: CommonScanTag{
				Source:    source,
				Timestamp: timestamp,
			},
			Value: r,
		})
	}

	for _, r := range ns {
		p.NSRecords = append(p.NSRecords, domainRecordValue{
			CommonScanTag: CommonScanTag{
				Source:    source,
				Timestamp: timestamp,
			},
			Value: r,
		})
	}

	for _, r := range ptr {
		p.PTRRecords = append(p.PTRRecords, domainRecordValue{
			CommonScanTag: CommonScanTag{
				Source:    source,
				Timestamp: timestamp,
			},
			Value: r,
		})
	}

	for _, r := range soa {
		p.SOARecords = append(p.SOARecords, domainRecordValue{
			CommonScanTag: CommonScanTag{
				Source:    source,
				Timestamp: timestamp,
			},
			Value: r,
		})
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
