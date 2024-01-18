package entities

import (
	"github.com/jackc/pgtype"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// NetworkNodeScan represents unique scanning procedure on a single defined network node.
type NetworkNodeScan struct {
	IsComplete bool `json:"IsComplete" gorm:"default:false;not null"`

	// Defines parent node, scan object belongs to node object (many-to-one)
	Node     *NetworkNode `json:"Node,omitempty" gorm:"foreignKey:NodeUUID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	NodeUUID pgtype.UUID  `json:"NodeUUID;type:uuid"`

	// Defines which agent provided current scan result
	Agent     *ScanAgent  `json:"Agent,omitempty" gorm:"foreignKey:AgentUUID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	AgentUUID pgtype.UUID `json:"AgentUUID;type:uuid"`

	Data datatypes.JSONType[NetworkNodeScanData] `json:"Data" gorm:"column:data"`

	gorm.Model
}

// NetworkNodeScanData represents contents of a NetworkNodeScan.
type NetworkNodeScanData struct {
}
