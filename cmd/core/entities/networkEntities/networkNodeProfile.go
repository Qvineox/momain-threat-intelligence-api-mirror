package networkEntities

import (
	"time"
)

type NetworkNodeProfile struct {
	IsBlacklisted bool `json:"IsBlacklisted"`

	ASNs []scanValue `json:"ASNs"`
	ISPs []scanValue `json:"ISPs"`

	Regions   []scanValue `json:"Regions"`
	Countries []scanValue `json:"Countries"`

	LatestScans []latestScan `json:"LatestScans"`
}

type latestScan struct {
	TypeID     ScanType  `json:"TypeID"`
	AssignedAt time.Time `json:"AssignedAt"`
}

type scanValue struct {
	Value      string    `json:"Value"`
	Source     string    `json:"Source"`
	AssignedAt time.Time `json:"AssignedAt"`
}
