package networkEntities

import (
	"gorm.io/gorm"
)

type NetworkNodeScanType struct {
	ID uint64 `json:"ID" gorm:"primaryKey"`

	Name        string `json:"Name" gorm:"column:name;size:64;not null;unique"`
	Description string `json:"Description" gorm:"column:description;size:128;default:No description."`

	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}

type ScanType uint64

const (
	SCAN_TYPE_OSS_VT_IP          ScanType = 101
	SCAN_TYPE_OSS_VT_DOMAIN               = 102
	SCAN_TYPE_OSS_VT_URL                  = 103
	SCAN_TYPE_OSS_IPQS_IP                 = 201
	SCAN_TYPE_OSS_IPQS_DOMAIN             = 202
	SCAN_TYPE_OSS_IPQS_URL                = 203
	SCAN_TYPE_OSS_IPQS_EMAIL              = 204
	SCAN_TYPE_OSS_SHODAN_IP               = 301
	SCAN_TYPE_OSS_CS_IP                   = 401
	SCAN_TYPE_OSS_IPWH_IP                 = 501
	SCAN_TYPE_OSS_CRIM_IP                 = 601
	SCAN_TYPE_OSS_CRIM_DOMAIN             = 602
	SCAN_TYPE_OSS_INFO_IP                 = 701
	SCAN_TYPE_OSS_IP_API_IP               = 801
	SCAN_TYPE_OSS_IP_API_DOMAIN           = 802
	SCAN_TYPE_DNS_LOOKUP                  = 1101
	SCAN_TYPE_DNS_REVERSE_LOOKUP          = 1102
	SCAN_TYPE_DNS_WHOIS_IP                = 1201
	SCAN_TYPE_DNS_WHOIS_DOMAIN            = 1202
)

var DefaultNetworkNodeScanTypes = []NetworkNodeScanType{
	{
		ID:          uint64(SCAN_TYPE_OSS_VT_IP),
		Name:        "VirusTotal IP",
		Description: "Данные об IP получены из запроса к API VirusTotal",
	},
	{
		ID:          uint64(SCAN_TYPE_OSS_VT_DOMAIN),
		Name:        "VirusTotal Domain",
		Description: "Данные о домене получены из запроса к API IPQualityScore",
	},
	{
		ID:          uint64(SCAN_TYPE_OSS_VT_URL),
		Name:        "VirusTotal URL",
		Description: "Данные о URL получены из запроса к API IPQualityScore",
	},
	{
		ID:          uint64(SCAN_TYPE_OSS_IPQS_IP),
		Name:        "IPQualityScore IP",
		Description: "Данные об IP получены из запроса к API IPQualityScore",
	},
	{
		ID:          uint64(SCAN_TYPE_OSS_IPQS_DOMAIN),
		Name:        "IPQualityScore Domain",
		Description: "Данные о домене получены из запроса к API IPQualityScore",
	},
	{
		ID:          uint64(SCAN_TYPE_OSS_IPQS_URL),
		Name:        "IPQualityScore URL",
		Description: "Данные о URL получены из запроса к API IPQualityScore",
	},
	{
		ID:          uint64(SCAN_TYPE_OSS_IPQS_EMAIL),
		Name:        "IPQualityScore Email",
		Description: "Данные об электронной почте получены из запроса к API IPQualityScore",
	},
	{
		ID:          uint64(SCAN_TYPE_OSS_SHODAN_IP),
		Name:        "Shodan IP",
		Description: "Данные об IP получены из запроса к API Shodan",
	},
	{
		ID:          uint64(SCAN_TYPE_OSS_CS_IP),
		Name:        "CrowdSec IP",
		Description: "Данные об IP получены из запроса к API CrowdSec",
	},
	{
		ID:          uint64(SCAN_TYPE_OSS_IPWH_IP),
		Name:        "IPWhoIs IP",
		Description: "Данные об IP получены из запроса к API IPWhoIS",
	},
	{
		ID:          uint64(SCAN_TYPE_OSS_CRIM_IP),
		Name:        "CriminalIP IP",
		Description: "Данные об IP получены из запроса к API CriminalIP",
	},
	{
		ID:          uint64(SCAN_TYPE_OSS_CRIM_DOMAIN),
		Name:        "CriminalIP Domain",
		Description: "Данные о домене получены из запроса к API CriminalIP",
	},
	{
		ID:          uint64(SCAN_TYPE_OSS_INFO_IP),
		Name:        "IPInfo IP",
		Description: "Данные об IP получены из запроса к API IPInfo",
	},
	{
		ID:          uint64(SCAN_TYPE_OSS_IP_API_IP),
		Name:        "IP-API IP",
		Description: "Данные об IP получены из запроса к API сервиса IP-API",
	},
	{
		ID:          uint64(SCAN_TYPE_OSS_IP_API_DOMAIN),
		Name:        "IP-API Domain",
		Description: "Данные о домене получены из запроса к API сервиса IP-API",
	},
	{
		ID:          uint64(SCAN_TYPE_DNS_LOOKUP),
		Name:        "DNS Lookup",
		Description: "Опрос системы доменных имен",
	},
	{
		ID:          uint64(SCAN_TYPE_DNS_REVERSE_LOOKUP),
		Name:        "DNS Reverse Lookup",
		Description: "Обратный опрос системы доменных имен по IP",
	},
	{
		ID:          uint64(SCAN_TYPE_DNS_WHOIS_IP),
		Name:        "WHOIS IP Lookup",
		Description: "Получение WHOIS информации об IP",
	},
	{
		ID:          uint64(SCAN_TYPE_DNS_WHOIS_DOMAIN),
		Name:        "WHOIS Domain Lookup",
		Description: "Получение WHOIS информации о домене",
	},
}
