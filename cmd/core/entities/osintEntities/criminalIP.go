package osintEntities

type CriminalIPIPScanBody struct {
	Ip string `json:"ip"`

	Issues struct {
		IsVpn          bool `json:"is_vpn"`
		IsCloud        bool `json:"is_cloud"`
		IsTor          bool `json:"is_tor"`
		IsProxy        bool `json:"is_proxy"`
		IsHosting      bool `json:"is_hosting"`
		IsMobile       bool `json:"is_mobile"`
		IsDarkweb      bool `json:"is_darkweb"`
		IsScanner      bool `json:"is_scanner"`
		IsSnort        bool `json:"is_snort"`
		IsAnonymousVpn bool `json:"is_anonymous_vpn"`
	} `json:"issues"`

	Score struct {
		Inbound  string `json:"inbound"`
		Outbound string `json:"outbound"`
	} `json:"score"`

	UserSearchCount int `json:"user_search_count"`

	ProtectedIp struct {
		Count int `json:"count"`
		Data  []struct {
			IpAddress     string `json:"ip_address"`
			ConfirmedTime string `json:"confirmed_time"`
		} `json:"data"`
	} `json:"protected_ip"`

	Domain struct {
		Count int `json:"count"`
		Data  []struct {
			Domain        string `json:"domain"`
			IpType        string `json:"ip_type"`
			Registrar     string `json:"registrar"`
			CreateDate    string `json:"create_date"`
			ConfirmedTime string `json:"confirmed_time"`
			Email         string `json:"email"`
		} `json:"data"`
	} `json:"domain"`

	Whois struct {
		Count int `json:"count"`
		Data  []struct {
			AsName         string  `json:"as_name"`
			AsNo           int     `json:"as_no"`
			City           string  `json:"city"`
			Region         string  `json:"region"`
			OrgName        string  `json:"org_name"`
			PostalCode     string  `json:"postal_code"`
			Longitude      float64 `json:"longitude"`
			Latitude       float64 `json:"latitude"`
			OrgCountryCode string  `json:"org_country_code"`
			ConfirmedTime  string  `json:"confirmed_time"`
		} `json:"data"`
	} `json:"whois"`

	Hostname struct {
		Count int `json:"count"`
		Data  []struct {
			DomainNameRep  string `json:"domain_name_rep"`
			DomainNameFull string `json:"domain_name_full"`
			ConfirmedTime  string `json:"confirmed_time"`
		} `json:"data"`
	} `json:"hostname"`

	Ids struct {
		Count int `json:"count"`
		Data  []struct {
			Classification string `json:"classification"`
			Url            string `json:"url"`
			Message        string `json:"message"`
			ConfirmedTime  string `json:"confirmed_time"`
			SourceSystem   string `json:"source_system"`
		} `json:"data"`
	} `json:"ids"`

	Vpn struct {
		Count int `json:"count"`
		Data  []struct {
			VpnName       string `json:"vpn_name"`
			VpnUrl        string `json:"vpn_url"`
			VpnSourceUrl  string `json:"vpn_source_url"`
			SocketType    string `json:"socket_type"`
			ConfirmedTime string `json:"confirmed_time"`
		} `json:"data"`
	} `json:"vpn"`

	AnonymousVpn struct {
		Count int `json:"count"`
		Data  []struct {
			VpnName       string `json:"vpn_name"`
			VpnUrl        string `json:"vpn_url"`
			VpnSourceUrl  string `json:"vpn_source_url"`
			SocketType    string `json:"socket_type"`
			ConfirmedTime string `json:"confirmed_time"`
		} `json:"data"`
	} `json:"anonymous_vpn"`

	Webcam struct {
		Count int `json:"count"`
		Data  []struct {
			ImagePath     string `json:"image_path"`
			CamUrl        string `json:"cam_url"`
			Country       string `json:"country"`
			City          string `json:"city"`
			OpenPortNo    int    `json:"open_port_no"`
			Manufacturer  string `json:"manufacturer"`
			ConfirmedTime string `json:"confirmed_time"`
		} `json:"data"`
	} `json:"webcam"`

	Honeypot struct {
		Count int `json:"count"`
		Data  []struct {
			IpAddress     string `json:"ip_address"`
			LogDate       string `json:"log_date"`
			DstPort       int    `json:"dst_port"`
			Message       string `json:"message"`
			UserAgent     string `json:"user_agent"`
			ProtocolType  string `json:"protocol_type"`
			ConfirmedTime string `json:"confirmed_time"`
		} `json:"data"`
	} `json:"honeypot"`

	IpCategory struct {
		Count int `json:"count"`
		Data  []struct {
			DetectSource string `json:"detect_source"`
			Type         string `json:"type"`
			DetectInfo   struct {
				Md5    string `json:"md5,omitempty"`
				Domain string `json:"domain,omitempty"`
			} `json:"detect_info"`
			ConfirmedTime string `json:"confirmed_time"`
		} `json:"data"`
	} `json:"ip_category"`

	Port struct {
		Count int `json:"count"`
		Data  []struct {
			AppName       string   `json:"app_name"`
			ConfirmedTime string   `json:"confirmed_time"`
			Banner        string   `json:"banner"`
			AppVersion    string   `json:"app_version"`
			OpenPortNo    int      `json:"open_port_no"`
			PortStatus    string   `json:"port_status"`
			Protocol      string   `json:"protocol"`
			Socket        string   `json:"socket"`
			Tags          []string `json:"tags"`
			DnsNames      string   `json:"dns_names"`
			SdnCommonName string   `json:"sdn_common_name"`
			JarmHash      string   `json:"jarm_hash"`
			SslInfoRaw    string   `json:"ssl_info_raw"`
			Technologies  []struct {
				TechName    string `json:"tech_name"`
				TechVersion string `json:"tech_version"`
				TechLogoUrl string `json:"tech_logo_url"`
			} `json:"technologies"`
			IsVulnerability bool `json:"is_vulnerability"`
		} `json:"data"`
	} `json:"port"`

	Vulnerability struct {
		Count int `json:"count"`
		Data  []struct {
			CveId          string  `json:"cve_id"`
			CveDescription string  `json:"cve_description"`
			Cvssv2Vector   string  `json:"cvssv2_vector"`
			Cvssv2Score    float64 `json:"cvssv2_score"`
			Cvssv3Vector   string  `json:"cvssv3_vector"`
			Cvssv3Score    float64 `json:"cvssv3_score"`
			ListCwe        []struct {
				CveId          string `json:"cve_id"`
				CweId          int    `json:"cwe_id"`
				CweName        string `json:"cwe_name"`
				CweDescription string `json:"cwe_description"`
			} `json:"list_cwe"`
			ListEdb []struct {
				CveId         string `json:"cve_id"`
				EdbId         int    `json:"edb_id"`
				Type          string `json:"type"`
				Platform      string `json:"platform"`
				VerifyCode    int    `json:"verify_code"`
				Title         string `json:"title"`
				ConfirmedTime string `json:"confirmed_time"`
			} `json:"list_edb"`
			AppName        string `json:"app_name"`
			AppVersion     string `json:"app_version"`
			OpenPortNoList struct {
				TCP []int         `json:"TCP"`
				UDP []interface{} `json:"UDP"`
			} `json:"open_port_no_list"`
			HaveMorePorts bool `json:"have_more_ports"`
			OpenPortNo    []struct {
				Port   int    `json:"port"`
				Socket string `json:"socket"`
			} `json:"open_port_no"`
			ListChild []struct {
				AppName    string `json:"app_name"`
				AppVersion string `json:"app_version"`
				Vendor     string `json:"vendor"`
				Type       string `json:"type"`
				IsVuln     string `json:"is_vuln"`
				TargetHw   string `json:"target_hw"`
				TargetSw   string `json:"target_sw"`
				Update     string `json:"update"`
				Edition    string `json:"edition"`
			} `json:"list_child"`
			Vendor   string `json:"vendor"`
			Type     string `json:"type"`
			IsVuln   string `json:"is_vuln"`
			TargetHw string `json:"target_hw"`
			TargetSw string `json:"target_sw"`
			Update   string `json:"update"`
			Edition  string `json:"edition"`
		} `json:"data"`
	} `json:"vulnerability"`

	Mobile struct {
		Count int `json:"count"`
		Data  []struct {
			Broadband    string `json:"broadband"`
			Organization string `json:"organization"`
		} `json:"data"`
	} `json:"mobile"`

	Status int `json:"status"`
}

func (report CriminalIPIPScanBody) GetRiskScore() *uint8 {
	var score = uint8(25.)

	return &score
}

type CriminalIPDomainScanBody struct {
	Data struct {
		Certificates []struct {
			CertificateLife string `json:"certificate_life"`
			Issuer          string `json:"issuer"`
			Protocol        string `json:"protocol"`
			Subject         string `json:"subject"`
			ValidFrom       string `json:"valid_from"`
			ValidTo         string `json:"valid_to"`
		} `json:"certificates"`

		Classification struct {
			DgaScore   float64 `json:"dga_score"`
			DomainType []struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"domain_type"`
			GoogleSafeBrowsing []interface{} `json:"google_safe_browsing"`
		} `json:"classification"`

		ConnectedDomainSubdomain []struct {
			MainDomain struct {
				Domain string `json:"domain"`
			} `json:"main_domain"`
			Subdomains []struct {
				Domain string `json:"domain"`
			} `json:"subdomains"`
		} `json:"connected_domain_subdomain"`

		ConnectedIp []struct {
			Ip    string `json:"ip"`
			Score string `json:"score"`
		} `json:"connected_ip"`

		ConnectedIpInfo []struct {
			AsName     string `json:"as_name"`
			Asn        string `json:"asn"`
			Cnt        int    `json:"cnt"`
			Country    string `json:"country"`
			DomainList []struct {
				Domain string `json:"domain"`
			} `json:"domain_list"`
			Ip          string `json:"ip"`
			RedirectCnt int    `json:"redirect_cnt"`
			Score       string `json:"score"`
		} `json:"connected_ip_info"`

		Cookies []struct {
			Domain   string `json:"domain"`
			Expires  string `json:"expires"`
			HttpOnly bool   `json:"http_only"`
			Name     string `json:"name"`
			Path     string `json:"path"`
			Secure   bool   `json:"secure"`
			Session  bool   `json:"session"`
			Value    string `json:"value"`
		} `json:"cookies"`

		DetectedProgram struct {
			ProgramDataInHtmlSource []struct {
				ExeName string `json:"exe_name"`
				ExeTag  string `json:"exe_tag"`
			} `json:"program_data_in_html_source"`
			ProgramDataWithAccess []struct {
				FileLink string `json:"file_link"`
				FileName string `json:"file_name"`
			} `json:"program_data_with_access"`
		} `json:"detected_program"`

		DnsRecord struct {
			DnsRecordTypeA struct {
				Ipv4 []struct {
					Ip    string `json:"ip"`
					Score string `json:"score"`
				} `json:"ipv4"`
				Ipv6 []struct {
					Ip    string `json:"ip"`
					Score string `json:"score"`
				} `json:"ipv6"`
			} `json:"dns_record_type_a"`
			DnsRecordTypeCname []string   `json:"dns_record_type_cname"`
			DnsRecordTypeMx    [][]string `json:"dns_record_type_mx"`
			DnsRecordTypeNs    []string   `json:"dns_record_type_ns"`
			DnsRecordTypePtr   []string   `json:"dns_record_type_ptr"`
			DnsRecordTypeSoa   []string   `json:"dns_record_type_soa"`
		} `json:"dns_record"`

		FileExposure struct {
			ApacheStatus bool `json:"apache_status"`
			DsStore      bool `json:"ds_store"`
			Firebase     bool `json:"firebase"`
			GitConfig    bool `json:"git_config"`
			JsonConfig   bool `json:"json_config"`
			Phpinfo      bool `json:"phpinfo"`
			Wordpress    bool `json:"wordpress"`
		} `json:"file_exposure"`

		Frames []struct {
			FrameId     string `json:"frame_id"`
			TransferCnt int    `json:"transfer_cnt"`
			Url         string `json:"url"`
		} `json:"frames"`

		HtmlPageLinkDomains []struct {
			Domain    string `json:"domain"`
			MappedIps []struct {
				AsName  string `json:"as_name"`
				Country string `json:"country"`
				Ip      string `json:"ip"`
				Score   string `json:"score"`
			} `json:"mapped_ips"`
			NslookupTime string `json:"nslookup_time"`
		} `json:"html_page_link_domains"`

		JavascriptVariables []struct {
			VariableName string `json:"variable_name"`
			VariableType string `json:"variable_type"`
		} `json:"javascript_variables"`

		Links []struct {
			Title string `json:"title"`
			Url   string `json:"url"`
		} `json:"links"`

		MainCertificate struct {
			Enddate         string `json:"enddate"`
			Issuer          string `json:"issuer"`
			SignedAlgorithm string `json:"signed_algorithm"`
			Startdate       string `json:"startdate"`
			Subject         string `json:"subject"`
		} `json:"main_certificate"`

		MainDomainInfo struct {
			ChangedUrl      string `json:"changed_url"`
			DnsIpAsn        string `json:"dns_ip_asn"`
			DomainCreated   string `json:"domain_created"`
			DomainRegistrar string `json:"domain_registrar"`
			DomainScore     struct {
				Score           string `json:"score"`
				ScoreNum        int    `json:"score_num"`
				ScorePercentage int    `json:"score_percentage"`
			} `json:"domain_score"`
			Favicon []struct {
				Hash string `json:"hash"`
				Link string `json:"link"`
			} `json:"favicon"`
			InsertedUrl string `json:"inserted_url"`
			Jarm        string `json:"jarm"`
			MainDomain  string `json:"main_domain"`
			RealIp      []struct {
				DnsIp       string `json:"dns_ip"`
				DnsIpScore  string `json:"dns_ip_score"`
				Port        string `json:"port"`
				RealIp      string `json:"real_ip"`
				RealIpScore string `json:"real_ip_score"`
			} `json:"real_ip"`
			Title string `json:"title"`
		} `json:"main_domain_info"`

		MappedIp []struct {
			AsName  string `json:"as_name"`
			Country string `json:"country"`
			Ip      string `json:"ip"`
			Score   string `json:"score"`
		} `json:"mapped_ip"`

		NetworkLogs struct {
			AbuseRecord struct {
				Count struct {
					Critical  int `json:"critical"`
					Dangerous int `json:"dangerous"`
				} `json:"count"`
				Data      []interface{} `json:"data"`
				ScoreData struct {
					CriticalList  []interface{} `json:"critical_list"`
					DangerousList []interface{} `json:"dangerous_list"`
				} `json:"score_data"`
			} `json:"abuse_record"`

			Data []struct {
				AsName       string `json:"as_name"`
				AsNumber     string `json:"as_number"`
				Country      string `json:"country"`
				DataSize     string `json:"data_size"`
				FrameId      string `json:"frame_id"`
				IpPort       string `json:"ip_port"`
				MimeType     string `json:"mime_type"`
				Protocol     string `json:"protocol"`
				Request      string `json:"request"`
				Score        string `json:"score"`
				Time         string `json:"time"`
				TransferSize string `json:"transfer_size"`
				Type         string `json:"type"`
				Url          string `json:"url"`
			} `json:"data"`
		} `json:"network_logs"`

		PageNetworkingInfo struct {
			ConnectedCountries string `json:"connected_countries"`
			Cookies            int    `json:"cookies"`
			Encryption         string `json:"encryption"`
			HttpsPercent       int    `json:"https_percent"`
			TlsCertificate     string `json:"tls_certificate"`
			TransactionCount   int    `json:"transaction_count"`
			TransferTraffic    string `json:"transfer_traffic"`
		} `json:"page_networking_info"`

		PageRedirections [][]struct {
			AsName      string `json:"as_name"`
			CountryCode string `json:"country_code"`
			Status      int    `json:"status"`
			Url         string `json:"url"`
		} `json:"page_redirections"`

		ReportTime  string   `json:"report_time"`
		Screenshots []string `json:"screenshots"`

		SecurityHeaders []struct {
			Header string `json:"header"`
			Value  string `json:"value"`
		} `json:"security_headers"`

		Ssl       bool `json:"ssl"`
		SslDetail struct {
			ForwardSecrecy struct {
				EllipticCurvesOffered string `json:"elliptic_curves_offered"`
				FiniteFieldGroup      string `json:"finite_field_group"`
				ForwardSecrecy        string `json:"forward_secrecy"`
				ForwardSecrecyCiphers string `json:"forward_secrecy_ciphers"`
			} `json:"forward_secrecy"`

			Headers struct {
				Cookies         string `json:"cookies"`
				Hsts            string `json:"hsts"`
				SecurityHeaders struct {
					CacheControl   string `json:"cache_control"`
					Pragma         string `json:"pragma"`
					ReferrerPolicy string `json:"referrer_policy"`
					XFrameOptions  string `json:"x_frame_options"`
					XXssProtection string `json:"x_xss_protection"`
				} `json:"security_headers"`
			} `json:"headers"`

			Protocols struct {
				DeprecatedSslProtocolVersions struct {
					Sslv2 string `json:"sslv2"`
					Sslv3 string `json:"sslv3"`
				} `json:"deprecated_ssl_protocol_versions"`
				TlsWarning string `json:"tls_warning"`
			} `json:"protocols"`

			ServerDefaults struct {
				ChainOfTrust         []string `json:"chain_of_trust"`
				DnsCaaRecord         []string `json:"dns_caa_record"`
				ServerKeySize        []string `json:"server_key_size"`
				TlsSessionResumption struct {
					Id      string `json:"id"`
					Tickets string `json:"tickets"`
				} `json:"tls_session_resumption"`
			} `json:"server_defaults"`

			Vulnerable struct {
				Beast struct {
					Tls1  string `json:"tls1"`
					Value string `json:"value"`
				} `json:"beast"`
				BreachAttacks                   string `json:"breach_attacks"`
				CcsInjection                    string `json:"ccs_injection"`
				ClientInitiatedSslRenegotiation string `json:"client_initiated_ssl_renegotiation"`
				CrimeTls                        string `json:"crime_tls"`
				Drown                           string `json:"drown"`
				Freak                           string `json:"freak"`
				Heartbleed                      string `json:"heartbleed"`
				Logjam                          string `json:"logjam"`
				Lucky13                         string `json:"lucky13"`
				Poodle                          string `json:"poodle"`
				Robot                           string `json:"robot"`
				SslRc4                          string `json:"ssl_rc4"`
				SslRenegotiation                string `json:"ssl_renegotiation"`
				Sweet32                         string `json:"sweet32"`
				Ticketbleed                     string `json:"ticketbleed"`
				TlsFallbackScsv                 string `json:"tls_fallback_scsv"`
				Winshock                        string `json:"winshock"`
			} `json:"vulnerable"`
		} `json:"ssl_detail"`

		Subdomains []struct {
			MainDomain struct {
				Domain string `json:"domain"`
			} `json:"main_domain"`
			Subdomains []struct {
				Domain string `json:"domain"`
			} `json:"subdomains"`
		} `json:"subdomains"`

		Summary struct {
			AbuseRecord struct {
				Critical  int `json:"critical"`
				Dangerous int `json:"dangerous"`
			} `json:"abuse_record"`
			AssociatedIp        string  `json:"associated_ip"`
			ConnectToIpDirectly int     `json:"connect_to_ip_directly"`
			CredInput           string  `json:"cred_input"`
			DgaScore            float64 `json:"dga_score"`
			DiffDomainFavicon   string  `json:"diff_domain_favicon"`
			FakeDomain          bool    `json:"fake_domain"`
			FakeHttpsUrl        bool    `json:"fake_https_url"`
			FakeSsl             struct {
				Category string `json:"category"`
				Invalid  bool   `json:"invalid"`
			} `json:"fake_ssl"`
			HiddenElement          int      `json:"hidden_element"`
			HiddenIframe           int      `json:"hidden_iframe"`
			Iframe                 int      `json:"iframe"`
			JsObfuscated           int      `json:"js_obfuscated"`
			ListOfCountries        []string `json:"list_of_countries"`
			MailServer             bool     `json:"mail_server"`
			MitmAttack             bool     `json:"mitm_attack"`
			NewbornDomain          string   `json:"newborn_domain"`
			OverlongDomain         bool     `json:"overlong_domain"`
			PhishingRecord         int      `json:"phishing_record"`
			Punycode               bool     `json:"punycode"`
			RealIp                 int      `json:"real_ip"`
			RedirectionDiffAsn     int      `json:"redirection_diff_asn"`
			RedirectionDiffCountry int      `json:"redirection_diff_country"`
			RedirectionDiffDomain  int      `json:"redirection_diff_domain"`
			RedirectionOnclick     string   `json:"redirection_onclick"`
			Sfh                    string   `json:"sfh"`
			Spf1                   string   `json:"spf1"`
			SuspiciousCookie       bool     `json:"suspicious_cookie"`
			SuspiciousElement      int      `json:"suspicious_element"`
			SuspiciousFile         int      `json:"suspicious_file"`
			SymbolUrl              bool     `json:"symbol_url"`
			UrlPhishingProb        float64  `json:"url_phishing_prob"`
			WebTraffic             string   `json:"web_traffic"`
		} `json:"summary"`

		Technologies []struct {
			Categories []string      `json:"categories"`
			Name       string        `json:"name"`
			Version    interface{}   `json:"version"`
			Vulner     []interface{} `json:"vulner"`
		} `json:"technologies"`
	} `json:"data"`

	Message string `json:"message"`
	Status  int    `json:"status"`
}

func (report CriminalIPDomainScanBody) GetRiskScore() *uint8 {
	var score = uint8(25.)

	return &score
}
