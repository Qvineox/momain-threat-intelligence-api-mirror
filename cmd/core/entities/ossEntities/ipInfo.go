package ossEntities

type IPInfoIPScanBody struct {
	Ip       string `json:"ip"`
	Hostname string `json:"hostname"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	Postal   string `json:"postal"`
	Timezone string `json:"timezone"`
}

func (report IPInfoIPScanBody) GetRiskScore() *uint8 {
	var score = uint8(25.)

	return &score
}
