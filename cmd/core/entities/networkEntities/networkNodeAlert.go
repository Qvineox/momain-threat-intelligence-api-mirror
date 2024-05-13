package networkEntities

type NetworkNodeAlert string

// low alerts
const (
	ALERT_LOW_GEO        NetworkNodeAlert = "GEO"      // Geographical filtering (not RU, not whitelisted)
	ALERT_LOW_CONTENT                     = "CONTENT"  // Web page content is not commonly used
	ALERT_LOW_NO_DATA                     = "UNKNOWN"  // Low amount or not enough scan data for node
	ALERT_LOW_NO_SCORING                  = "NO SCORE" // Network node has not been analyzed yet
	ALERT_LOW_DARK_WEB                    = "DARK WEB" // Network node might be a part of dark web
	ALERT_LOW_GENERIC                     = "GENERIC"  // Generic email or domain provided by ISP
	ALERT_LOW_TLD                         = "TLD"      // Usage of an uncommon TLD
	ALERT_LOW_HOSTING                     = "HOSTING"  // Network node is owned by VPS provider
)

// medium alerts
const (
	ALERT_MID_GEO         NetworkNodeAlert = "GEO"         // Geographical filtering (not RU, blacklists)
	ALERT_MID_CONTENT                      = "CONTENT"     // Suspicious content discovered
	ALERT_MID_PRIVACY                      = "PRIVACY"     // VPN, PROXY or TOR
	ALERT_MID_SEMANTIC                     = "SEMANTIC"    // Semantic analysis
	ALERT_MID_SPAM                         = "SPAM"        // Network node sends SPAM messages
	ALERT_MID_BLACKLISTED                  = "BLACKLISTED" // Network node is blacklisted in external sources
	ALERT_MID_TLD                          = "TLD"         // Usage of a very uncommon TLD
	ALERT_MID_TRAFFIC                      = "TRAFFIC"     // Suspicious traffic found
)

// high alerts
const (
	ALERT_HIGH_DGA         NetworkNodeAlert = "DGA"         // Network node name is generated
	ALERT_HIGH_MALWARE                      = "MALWARE"     // Network node distributes malware
	ALERT_HIGH_PHISHING                     = "PHISHING"    // Network node is a phishing resource
	ALERT_HIGH_BLACKLISTED                  = "BLACKLISTED" // Network node is blacklisted in a system
	ALERT_HIGH_SCORING                      = "SCORING"     // Machine learning scoring high risk value
)
