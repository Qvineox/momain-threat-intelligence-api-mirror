package networkEntities

import (
	"bytes"
	"domain_threat_intelligence_api/cmd/core/entities/dnsEntities"
	"domain_threat_intelligence_api/cmd/core/entities/osintEntities"
	"domain_threat_intelligence_api/cmd/core/entities/whoisEntities"
	"encoding/json"
	"github.com/jackc/pgtype"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"log/slog"
	"time"
)

// NetworkNodeScan represents unique scanning procedure on a single defined network node.
type NetworkNodeScan struct {
	ID uint64 `json:"ID" gorm:"primaryKey"`

	IsComplete bool `json:"IsComplete" gorm:"default:false;not null"`

	// Defines parent node, scan object belongs to node object (many-to-one)
	Node     *NetworkNode `json:"Node,omitempty" gorm:"foreignKey:NodeUUID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	NodeUUID pgtype.UUID  `json:"NodeUUID"`

	ScanType   *NetworkNodeScanType `json:"Type,omitempty" gorm:"foreignKey:ScanTypeID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	ScanTypeID uint64               `json:"TypeID"`

	// RiskScore is a final audit result. Determines if host is malicious or not. Lower is better.
	RiskScore *uint8 `json:"RiskScore" gorm:"column:scoring"`

	// Defines in which job scan result was created
	JobUUID *pgtype.UUID `json:"JobUUID"`

	Data datatypes.JSON `json:"Data,omitempty" gorm:"column:data"`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}

// NetworkNodeScanData represents contents of a NetworkNodeScan.
type NetworkNodeScanData struct {
}

// ProcessCollectedData scans collected byte data from sources, compacts and clears it, removing redundant data.
// Inserts processed JSON into database. Also evaluates starting RiskScore from scanned data.
func (scan *NetworkNodeScan) ProcessCollectedData(data []byte) error {
	var err error

	switch ScanType(scan.ScanTypeID) {
	case SCAN_TYPE_OSS_VT_IP:
		content := osintEntities.VTIPScanBody{}
		err = json.Unmarshal(data, &content)

		scan.RiskScore = content.GetRiskScore()
		data, err = json.Marshal(content.Data)
		break

	case SCAN_TYPE_OSS_VT_DOMAIN:
		content := osintEntities.VTDomainScanBody{}
		err = json.Unmarshal(data, &content)
		if err != nil {
			return err
		}

		scan.RiskScore = content.GetRiskScore()
		data, err = json.Marshal(content.Data)
		break

	case SCAN_TYPE_OSS_VT_URL:
		content := osintEntities.VTURLScanBody{}
		err = json.Unmarshal(data, &content)
		if err != nil {
			return err
		}

		scan.RiskScore = content.GetRiskScore()
		data, err = json.Marshal(content.Data)
		break

	case SCAN_TYPE_OSS_IPQS_IP:
		content := osintEntities.IPQSPrivacyScanBody{}
		err = json.Unmarshal(data, &content)
		if err != nil {
			return err
		}

		scan.RiskScore = content.GetRiskScore()
		break

	case SCAN_TYPE_OSS_IPQS_DOMAIN:
		content := osintEntities.IPQSMaliciousURLScanBody{}
		err = json.Unmarshal(data, &content)

		scan.RiskScore = content.GetRiskScore()
		break

	case SCAN_TYPE_OSS_IPQS_URL:
		content := osintEntities.IPQSMaliciousURLScanBody{}
		err = json.Unmarshal(data, &content)

		scan.RiskScore = content.GetRiskScore()
		break

	case SCAN_TYPE_OSS_IPQS_EMAIL:
		content := osintEntities.IPQSEMailScanBody{}
		err = json.Unmarshal(data, &content)
		if err != nil {
			return err
		}

		scan.RiskScore = content.GetRiskScore()
		break

	case SCAN_TYPE_OSS_SHODAN_IP:
		content := osintEntities.ShodanHostScanBody{}
		err = json.Unmarshal(data, &content)
		if err != nil {
			return err
		}

		scan.RiskScore = content.GetRiskScore()
		break

	case SCAN_TYPE_OSS_CS_IP:
		content := osintEntities.CrowdSecIPScanBody{}
		err = json.Unmarshal(data, &content)
		if err != nil {
			return err
		}

		scan.RiskScore = content.GetRiskScore()
		break

	case SCAN_TYPE_OSS_CRIM_IP:
		content := osintEntities.CriminalIPIPScanBody{}
		err = json.Unmarshal(data, &content)
		if err != nil {
			return err
		}

		scan.RiskScore = content.GetRiskScore()
		break

	case SCAN_TYPE_OSS_CRIM_DOMAIN:
		content := osintEntities.CriminalIPDomainScanBody{}
		err = json.Unmarshal(data, &content)
		if err != nil {
			return err
		}

		scan.RiskScore = content.GetRiskScore()
		break

	case SCAN_TYPE_OSS_INFO_IP:
		content := osintEntities.IPInfoIPScanBody{}
		err = json.Unmarshal(data, &content)
		if err != nil {
			return err
		}

		scan.RiskScore = content.GetRiskScore()
		break

	case SCAN_TYPE_OSS_IP_API_IP, SCAN_TYPE_OSS_IP_API_DOMAIN:
		content := osintEntities.IPAPIScanBody{}
		err = json.Unmarshal(data, &content)
		if err != nil {
			return err
		}

		scan.RiskScore = content.GetRiskScore()
		break

	case SCAN_TYPE_DNS_LOOKUP:
		content := dnsEntities.DNSLookupScanBody{}
		err = json.Unmarshal(data, &content)
		if err != nil {
			return err
		}

		break

	case SCAN_TYPE_DNS_REVERSE_LOOKUP:
		content := dnsEntities.ReverseDNSLookupScanBody{}
		err = json.Unmarshal(data, &content)
		if err != nil {
			return err
		}

		break

	case SCAN_TYPE_WHOIS_IP, SCAN_TYPE_WHOIS_DOMAIN:
		content := whoisEntities.WhoISScanBody{}
		err = json.Unmarshal(data, &content)
		if err != nil {
			return err
		}

		break

	// TODO: add compacting, remove redundant or null (N/A, or other) fields
	default:
		slog.Warn("unsupported marshal type")
	}

	if err != nil {
		return err
	}

	dst := &bytes.Buffer{}
	if err = json.Compact(dst, data); err != nil {
		return err
	}

	scan.Data = dst.Bytes()

	return nil
}
