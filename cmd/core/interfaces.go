package core

import (
	"domain_threat_intelligence_api/cmd/core/entities/agentEntities"
	"domain_threat_intelligence_api/cmd/core/entities/authEntities"
	"domain_threat_intelligence_api/cmd/core/entities/blacklistEntities"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"domain_threat_intelligence_api/cmd/core/entities/networkEntities"
	"domain_threat_intelligence_api/cmd/core/entities/serviceDeskEntities"
	"domain_threat_intelligence_api/cmd/core/entities/userEntities"
	"github.com/jackc/pgtype"
	"time"
)

type IBlacklistsService interface {
	RetrieveIPsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedIP, error)
	SaveIPs([]blacklistEntities.BlacklistedIP) (int64, error)
	DeleteIP(uuid pgtype.UUID) (int64, error)

	RetrieveDomainsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedDomain, error)
	SaveDomains([]blacklistEntities.BlacklistedDomain) (int64, error)
	DeleteDomain(uuid pgtype.UUID) (int64, error)

	RetrieveURLsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedURL, error)
	SaveURLs([]blacklistEntities.BlacklistedURL) (int64, error)
	DeleteURL(uuid pgtype.UUID) (int64, error)

	RetrieveEmailsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedEmail, error)
	SaveEmails([]blacklistEntities.BlacklistedEmail) (int64, error)
	DeleteEmail(uuid pgtype.UUID) (int64, error)

	SaveImportEvent(event blacklistEntities.BlacklistImportEvent) (blacklistEntities.BlacklistImportEvent, error)
	RetrieveImportEventsByFilter(filter blacklistEntities.BlacklistImportEventFilter) ([]blacklistEntities.BlacklistImportEvent, error)
	RetrieveImportEvent(id uint64) (blacklistEntities.BlacklistImportEvent, error)
	DeleteImportEvent(id uint64) (int64, error)

	RetrieveHostsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedHost, error)

	ImportFromSTIX2(bundles []blacklistEntities.STIX2Bundle, extractAll bool) (blacklistEntities.BlacklistImportEvent, error)
	ImportFromCSV(data [][]string, discoveredAt time.Time, extractAll bool) (blacklistEntities.BlacklistImportEvent, error)

	ExportToJSON(blacklistEntities.BlacklistSearchFilter) ([]byte, error)
	ExportToCSV(blacklistEntities.BlacklistSearchFilter) ([]byte, error)
	ExportToNaumen(filter blacklistEntities.BlacklistSearchFilter) (serviceDeskEntities.ServiceDeskTicket, error)

	RetrieveTotalStatistics() (ips int64, urls int64, domains int64, emails int64)
	RetrieveByCreationDateStatistics(startDate, endDate time.Time) ([]blacklistEntities.BlacklistedByDate, error)
	RetrieveByDiscoveryDateStatistics(startDate, endDate time.Time) ([]blacklistEntities.BlacklistedByDate, error)

	RetrieveAllSources() ([]blacklistEntities.BlacklistSource, error)
}

type IBlacklistsRepo interface {
	SelectIPsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedIP, error)
	SaveIPs([]blacklistEntities.BlacklistedIP) (int64, error)
	DeleteIP(uuid pgtype.UUID) (int64, error)

	SelectDomainsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedDomain, error)
	SaveDomains([]blacklistEntities.BlacklistedDomain) (int64, error)
	DeleteDomain(uuid pgtype.UUID) (int64, error)

	SelectURLsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedURL, error)
	SaveURLs([]blacklistEntities.BlacklistedURL) (int64, error)
	DeleteURL(uuid pgtype.UUID) (int64, error)

	SelectEmailsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedEmail, error)
	SaveEmails([]blacklistEntities.BlacklistedEmail) (int64, error)
	DeleteEmail(uuid pgtype.UUID) (int64, error)

	SaveImportEvent(event blacklistEntities.BlacklistImportEvent) (blacklistEntities.BlacklistImportEvent, error)
	SelectImportEventsByFilter(filter blacklistEntities.BlacklistImportEventFilter) ([]blacklistEntities.BlacklistImportEvent, error)
	SelectImportEvent(id uint64) (blacklistEntities.BlacklistImportEvent, error)
	DeleteImportEvent(id uint64) (int64, error)

	SelectHostsUnionByFilter(filter blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedHost, error)

	CountStatistics() (ips int64, urls int64, domains int64, emails int64)
	SelectByCreationDateStatistics(startDate, endDate time.Time) ([]blacklistEntities.BlacklistedByDate, error)
	SelectByDiscoveryDateStatistics(startDate, endDate time.Time) ([]blacklistEntities.BlacklistedByDate, error)

	SelectAllSources() ([]blacklistEntities.BlacklistSource, error)
}

type IQueueService interface {
	QueueNewJob(params jobEntities.JobCreateParams) (*pgtype.UUID, error)

	// AlterQueuedJob modifies jobs in queue, cannot change running jobs on agents
	AlterQueuedJob(uuid *pgtype.UUID, params jobEntities.JobCreateParams) (*pgtype.UUID, error)

	// CancelQueuedJob removes job from queue, can also stop it on agent
	CancelQueuedJob(uuid *pgtype.UUID, force bool) error

	// RetrieveAllJobs returns all jobs from queue and agents
	RetrieveAllJobs() [3][]*jobEntities.Job

	RetrieveConnectedAgentsUUIDs() []pgtype.UUID
}

type INetworkNodesService interface {
	RetrieveNetworkNodeByUUID(uuid pgtype.UUID) (networkEntities.NetworkNode, error)
	RetrieveNetworkNodesByFilter(filter networkEntities.NetworkNodeSearchFilter) ([]networkEntities.NetworkNode, error)

	SaveNetworkNode(node networkEntities.NetworkNode) (networkEntities.NetworkNode, error)
	DeleteNetworkNode(uuid pgtype.UUID) (int64, error)

	// EvaluateNetworkNodeScoring queries node from database, evaluates scoring via IScoringService and saves new values
	EvaluateNetworkNodeScoring(uuid pgtype.UUID) (networkEntities.NetworkNode, error)

	SaveNetworkNodeWithIdentity(scan networkEntities.NetworkNodeScan, target jobEntities.Target) (uuid pgtype.UUID, err error)
}

type INetworkNodesRepo interface {
	SelectNetworkNodeByUUID(uuid pgtype.UUID) (networkEntities.NetworkNode, error)
	SelectNetworkNodesByFilter(filter networkEntities.NetworkNodeSearchFilter) ([]networkEntities.NetworkNode, error)
	SaveNetworkNode(node networkEntities.NetworkNode) (networkEntities.NetworkNode, error)
	DeleteNetworkNode(uuid pgtype.UUID) (int64, error)

	// SelectOrCreateByTarget returns node data by ID, domain, URL or email. Creates new node if it doesn't exist.
	SelectOrCreateByTarget(target jobEntities.Target) (networkEntities.NetworkNode, error)

	// SaveNetworkNodeScan creates or updates new network node scan.
	SaveNetworkNodeScan(scan networkEntities.NetworkNodeScan) (networkEntities.NetworkNodeScan, error)

	// CreateNetworkNodeWithIdentity creates new network node scan via SaveNetworkNodeScan.
	// Also creates new node from host value, if it doesn't exist via SelectOrCreateByTarget.
	CreateNetworkNodeWithIdentity(scan networkEntities.NetworkNodeScan, target jobEntities.Target) (uuid pgtype.UUID, err error)
}

type IScoringService interface {
	// AnalyzeNodes adds scoring values into networkEntities.NetworkNode's Scoring field and returns them
	AnalyzeNodes(nodes []networkEntities.NetworkNode) ([]networkEntities.NetworkNode, error)
}

type IJobsService interface {
	RetrieveJobsByFilter(filter jobEntities.JobsSearchFilter) ([]jobEntities.Job, error)
	RetrieveJobByUUID(uuid pgtype.UUID) (jobEntities.Job, error)
	SaveJob(job *jobEntities.Job) error
	DeleteJob(uuid pgtype.UUID) (rows int64, err error)
}

type IJobsRepo interface {
	SelectJobsByFilter(filter jobEntities.JobsSearchFilter) ([]jobEntities.Job, error)
	SelectJobByUUID(uuid pgtype.UUID) (jobEntities.Job, error)
	SaveJob(job *jobEntities.Job) error
	DeleteJob(uuid pgtype.UUID) (rows int64, err error)
}

type IAgentsService interface {
	RetrieveAllAgents() ([]agentEntities.ScanAgent, error)
	RetrieveAgentByUUID(uuid pgtype.UUID) (agentEntities.ScanAgent, error)

	CreateAgent(agent agentEntities.ScanAgent) (agentEntities.ScanAgent, error)
	UpdateAgent(agent agentEntities.ScanAgent) (agentEntities.ScanAgent, error)
	DeleteAgent(uuid pgtype.UUID) error
}

type IAgentsRepo interface {
	SelectAllAgents() ([]agentEntities.ScanAgent, error)
	SelectAgentByUUID(uuid pgtype.UUID) (agentEntities.ScanAgent, error)

	SaveAgent(agent agentEntities.ScanAgent) (agentEntities.ScanAgent, error)
	DeleteAgent(uuid pgtype.UUID) error
}

type IUsersService interface {
	// SaveUser updates only existing entities.PlatformUser, returns error if user doesn't exist, ID must be defined.
	// This method doesn't update user password, use ResetPassword or ChangePassword
	SaveUser(user userEntities.PlatformUser, permissionIDs []uint64) error

	CreateUser(user userEntities.PlatformUser, password string, permissionIDs []uint64) (uint64, error)

	DeleteUser(id uint64) (int64, error)
	RetrieveUsers() ([]userEntities.PlatformUser, error)
	RetrieveUser(id uint64) (userEntities.PlatformUser, error)

	RetrievePermissions() ([]userEntities.PlatformUserPermission, error)
	RetrievePermissionPresets() []userEntities.PlatformUserRolesPreset

	// ResetPassword is used to send recovery messages to users
	ResetPassword(id uint64) error

	// ChangePassword allows to set new password for user. Can be used by admin and user itself
	ChangePassword(id uint64, oldPassword, newPassword string) error
}

type IUsersRepo interface {
	InsertUser(user userEntities.PlatformUser) (uint64, error)
	UpdateUser(user userEntities.PlatformUser) error
	DeleteUser(id uint64) (int64, error)

	SelectUsers() ([]userEntities.PlatformUser, error)
	SelectUser(id uint64) (userEntities.PlatformUser, error)
	SelectUserByLogin(login string) (userEntities.PlatformUser, error)
	SelectUserByRefreshToken(token string) (userEntities.PlatformUser, error)

	SelectPermissions() ([]userEntities.PlatformUserPermission, error)

	// UpdateUserWithPasswordHash is used only to update user password hash. Must be used when resetting or changing password
	UpdateUserWithPasswordHash(user userEntities.PlatformUser) error

	// UpdateUserWithRefreshToken is used only to update user refresh token. Must be used when resetting token, on login and logout.
	UpdateUserWithRefreshToken(user userEntities.PlatformUser) error
}

type IAuthService interface {
	ConfirmEmail(confirmationUUID pgtype.UUID) error

	// Register creates new entities.PlatformUser, returns error if user exists, ignores defined ID
	Register(login, password, fullName, email string, roleIDs []uint64) (uint64, error)
	Login(login, password string) (userID uint64, accessToken, refreshToken string, err error)
	Logout(refreshToken string) (uint64, error)

	ChangePassword(user userEntities.PlatformUser, oldPassword, newPassword string) (userEntities.PlatformUser, error)
	ResetPassword(user userEntities.PlatformUser, newPassword string) (userEntities.PlatformUser, error)

	Validate(accessToken string) (claims authEntities.AccessTokenClaims, err error)
	Refresh(refreshToken string) (id uint64, accessToken, newRefreshToken string, err error)

	GetPasswordStrength(password string) (level int, time, entropy float64)
	GetDomain() string
}

// ISystemStateService holds collection of services that provide info about system configuration, state and status
type ISystemStateService interface {
	RetrieveDynamicConfig() ([]byte, error)
	ReturnToDefault() error

	UpdateSMTPConfig(enabled, SSL, UseAuth bool, host, user, from, password string, port int) error
	UpdateNSDCredentials(enabled bool, host, clientKey string, clientID, clientGroupID uint64) error
	UpdateNSDBlacklistServiceConfig(id, slm uint64, callType string, types []string) error
}

type IServiceDeskService interface {
	IsAvailable() bool

	RetrieveTicketsByFilter(filter serviceDeskEntities.ServiceDeskSearchFilter) ([]serviceDeskEntities.ServiceDeskTicket, error)
	DeleteTicket(id uint64) error

	// SendBlacklistedHosts sends new ticket to service desk
	SendBlacklistedHosts([]blacklistEntities.BlacklistedHost) (ticket serviceDeskEntities.ServiceDeskTicket, err error)
}

type ISMTPService interface {
	SendMessage(to, cc, bcc []string, subject, body string) error
}

type IServiceDeskRepo interface {
	SaveTicket(ticket serviceDeskEntities.ServiceDeskTicket) (serviceDeskEntities.ServiceDeskTicket, error)
	SelectTicketsByFilter(filter serviceDeskEntities.ServiceDeskSearchFilter) ([]serviceDeskEntities.ServiceDeskTicket, error)
	DeleteTicket(id uint64) error
	// SelectTicket(id uint64)
}
