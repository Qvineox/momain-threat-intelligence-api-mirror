package dnsEntities

type DNSLookupScanBody struct {
	Host string `json:"host"`

	IPs           []string            `json:"ips"`
	ReverseLookup map[string][]string `json:"reverse"`

	CanonicalName string `json:"cname"`

	MailServers    []string `json:"mx"`
	NameServers    []string `json:"ns"`
	TextRecords    []string `json:"txt"`
	PointerRecords []string `json:"ptr"`
}
