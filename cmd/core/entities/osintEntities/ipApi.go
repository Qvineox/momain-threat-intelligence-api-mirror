package osintEntities

type IPAPIScanBody struct {
	Query string `json:"query"`

	AS           string `json:"as"`
	ASName       string `json:"asname"`
	ISP          string `json:"isp"`
	Organisation string `json:"org"`

	Latitude  float64 `json:"lat"`
	Longitude float64 `json:"lon"`

	Zip         string `json:"zip"`
	City        string `json:"city"`
	Region      string `json:"region"`
	RegionName  string `json:"regionName"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	Continent   string `json:"continent"`
	Timezone    string `json:"timezone"`

	IsProxy   bool `json:"proxy"`
	IsHosting bool `json:"hosting"`

	Mobile  bool   `json:"mobile"`
	Status  string `json:"status"`
	Reverse string `json:"reverse"`
}

func (report IPAPIScanBody) GetRiskScore() *uint8 {
	var score = uint8(25.)

	return &score
}
