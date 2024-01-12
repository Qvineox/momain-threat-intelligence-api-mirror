package entities

import (
	"github.com/jackc/pgtype"
	"gorm.io/gorm"
)

type BlacklistedIP struct {
	IPAddress pgtype.Inet `json:"ip_address" gorm:"column:ip_address;type:inet;not_null"`

	// Defines source from where blacklisted host was added
	Source   BlacklistSource `json:"source" gorm:"foreignKey:SourceID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	SourceID uint64          `json:"source_id"`

	gorm.Model
}
