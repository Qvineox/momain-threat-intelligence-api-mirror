package networkEntities

import (
	"time"
)

type NetworkNodeProfile struct {

	// owner identity data
	ASNs          []scanStringValue `json:"ASNs"`
	ISPs          []scanStringValue `json:"ISPs"`
	JARMs         []scanStringValue `json:"JARMs"`
	Organisations []scanStringValue `json:"Organisations"`

	// geographical data
	Regions   []scanStringValue `json:"Regions"`
	Countries []scanStringValue `json:"Countries"`

	// blacklists data
	IsBlacklisted      bool                `json:"IsBlacklisted"`      // IsBlacklisted for internal blacklisting
	ExternalBlacklists []externalBlacklist `json:"ExternalBlacklists"` // ExternalBlacklists from external blacklists (i.e. VirusTotal)

	// scoring
	ProviderScores []scanIntValue `json:"ProviderScores"`
	DGAScore       float32        `json:"DGAScore"`
	SemanticScore  float32        `json:"SemanticScore"`
	DNSScore       float32        `json:"DNSScore"`
	OverallScore   float32        `json:"OverallScore"`
	IsMalicious    bool           `json:"IsMalicious"`

	// latest scanning data
	LatestScans []latestScan `json:"LatestScans"`
}

type latestScan struct {
	TypeID     ScanType  `json:"TypeID"`
	AssignedAt time.Time `json:"AssignedAt"`
}

type scanStringValue struct {
	Value      string    `json:"Value"`
	Source     string    `json:"Source"`
	AssignedAt time.Time `json:"AssignedAt"`
}

type scanIntValue struct {
	Value      int       `json:"Value"`
	Source     string    `json:"Source"`
	AssignedAt time.Time `json:"AssignedAt"`
}

type externalBlacklist struct {
	Source       string    `json:"Source"`
	DiscoveredAt time.Time `json:"DiscoveredAt"`
}

func (p *NetworkNodeProfile) WithBlacklisted(isBlacklisted bool) *NetworkNodeProfile {
	p.IsBlacklisted = isBlacklisted
	return p
}

func (p *NetworkNodeProfile) WithNodeScans(scans []NetworkNodeScan) *NetworkNodeProfile {
	// todo: add profile filament

	return p
}
