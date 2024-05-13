package networkEntities

import (
	"gorm.io/gorm"
	"time"
)

// NetworkNodeType is linked to jobEntities.TargetType
type NetworkNodeType struct {
	ID uint64 `json:"ID" gorm:"primaryKey"`

	Name        string `json:"Name" gorm:"column:name;size:64;not null;unique"`
	Description string `json:"Description" gorm:"column:description;size:128;default:No description."`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}

type NetworkNodeTypeID uint64

const (
	NETWORK_NODE_TYPE_IP     NetworkNodeTypeID = 1
	NETWORK_NODE_TYPE_DOMAIN                   = 2
	NETWORK_NODE_TYPE_EMAIL                    = 3
	NETWORK_NODE_TYPE_URL                      = 4
)

// DefaultNetworkNodeTypes has equal IDs to jobEntities.TargetType
var DefaultNetworkNodeTypes = []NetworkNodeType{
	{
		ID:          uint64(NETWORK_NODE_TYPE_IP),
		Name:        "CIDR/IP",
		Description: "IP address",
	},
	{
		ID:          uint64(NETWORK_NODE_TYPE_DOMAIN),
		Name:        "Domain",
		Description: "Internet Domain",
	},
	{
		ID:          uint64(NETWORK_NODE_TYPE_EMAIL),
		Name:        "EMail",
		Description: "Email address",
	},
	{
		ID:          uint64(NETWORK_NODE_TYPE_URL),
		Name:        "URL",
		Description: "URL address",
	},
}
