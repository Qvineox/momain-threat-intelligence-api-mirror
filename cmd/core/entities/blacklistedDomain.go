package entities

import "gorm.io/gorm"

type BlacklistedDomain struct {
	URN         string `json:"URN" gorm:"column:urn;not_null;uniqueIndex:idx_domain"`
	Description string `json:"Description" gorm:"column:description"`

	// Defines source from where blacklisted host was added
	Source   *BlacklistSource `json:"Source,omitempty" gorm:"foreignKey:SourceID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	SourceID uint64           `json:"SourceID" gorm:"uniqueIndex:idx_domain"`

	gorm.Model
}
