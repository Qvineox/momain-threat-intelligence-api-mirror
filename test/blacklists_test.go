package test

import (
	"domain_threat_intelligence_api/cmd/app"
	"domain_threat_intelligence_api/cmd/core/entities/blacklistEntities"
	"domain_threat_intelligence_api/cmd/core/repos"
	"domain_threat_intelligence_api/cmd/core/services"
	"domain_threat_intelligence_api/configs"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"os"
	"testing"
	"time"
)

func TestBlacklists(t *testing.T) {
	config, err := configs.NewTestConfig()
	require.NoError(t, err)

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s database=%s sslmode=disable TimeZone=%s", config.Database.Host, config.Database.Port, config.Database.User, config.Database.Password, config.Database.Name, config.Database.Timezone)
	dbConn, err := gorm.Open(postgres.Open(dsn))

	err = app.Migrate(dbConn)
	require.NoError(t, err)

	blacklistRepo := repos.NewBlacklistsRepoImpl(dbConn)
	blacklistService := services.NewBlackListsServiceImpl(blacklistRepo, nil)

	err = clearBlacklists(t, blacklistRepo)
	require.NoError(t, err)

	t.Run("finCert STIX json file parsing", func(t *testing.T) {
		var bundle blacklistEntities.STIX2Bundle

		file, err := os.ReadFile("./files/fincert_blacklists/FinCERT_20240509-153945.json")
		require.NoError(t, err)

		err = json.Unmarshal(file, &bundle)
		require.NoError(t, err)
		require.NotNil(t, file)

		importedValues, err := blacklistService.ImportFromSTIX2([]blacklistEntities.STIX2Bundle{bundle}, false)
		require.NoError(t, err)
		require.NotNil(t, importedValues)

		summaryImport := importedValues.Summary.Data().Imported
		require.EqualValues(t, 27, summaryImport.IPs)
		require.EqualValues(t, 33, summaryImport.URLs)
		require.EqualValues(t, 70, summaryImport.Domains)
		require.EqualValues(t, 0, summaryImport.Emails)

		summaryAffected := importedValues.Summary.Data().Affected
		require.EqualValues(t, 27, summaryAffected.IPs)
		require.EqualValues(t, 33, summaryAffected.URLs)
		require.EqualValues(t, 70, summaryAffected.Domains)
		require.EqualValues(t, 0, summaryAffected.Emails)

		summaryNew := importedValues.Summary.Data().New
		require.EqualValues(t, 27, summaryNew.IPs)
		require.EqualValues(t, 33, summaryNew.URLs)
		require.EqualValues(t, 70, summaryNew.Domains)
		require.EqualValues(t, 0, summaryNew.Emails)
	})

	t.Run("finCert STIX json file repeated import", func(t *testing.T) {
		var bundle blacklistEntities.STIX2Bundle

		file, err := os.ReadFile("./files/fincert_blacklists/FinCERT_20240509-153945.json")
		require.NoError(t, err)

		err = json.Unmarshal(file, &bundle)
		require.NoError(t, err)
		require.NotNil(t, file)

		importedValues, err := blacklistService.ImportFromSTIX2([]blacklistEntities.STIX2Bundle{bundle}, false)
		require.NoError(t, err)
		require.NotNil(t, importedValues)

		summaryImport := importedValues.Summary.Data().Imported
		require.EqualValues(t, 27, summaryImport.IPs)
		require.EqualValues(t, 33, summaryImport.URLs)
		require.EqualValues(t, 70, summaryImport.Domains)
		require.EqualValues(t, 0, summaryImport.Emails)

		summaryAffected := importedValues.Summary.Data().Affected
		require.EqualValues(t, 27, summaryAffected.IPs)
		require.EqualValues(t, 33, summaryAffected.URLs)
		require.EqualValues(t, 70, summaryAffected.Domains)
		require.EqualValues(t, 0, summaryAffected.Emails)

		summaryNew := importedValues.Summary.Data().New
		require.EqualValues(t, 0, summaryNew.IPs)
		require.EqualValues(t, 0, summaryNew.URLs)
		require.EqualValues(t, 0, summaryNew.Domains)
		require.EqualValues(t, 0, summaryNew.Emails)
	})

	err = clearBlacklists(t, blacklistRepo)
	require.NoError(t, err)

	t.Run("host additional extraction from stix json", func(t *testing.T) {
		var bundle blacklistEntities.STIX2Bundle

		file, err := os.ReadFile("./files/fincert_blacklists/FinCERT_20240509-153945.json")
		require.NoError(t, err)

		err = json.Unmarshal(file, &bundle)
		require.NoError(t, err)
		require.NotNil(t, file)

		importedValues, err := blacklistService.ImportFromSTIX2([]blacklistEntities.STIX2Bundle{bundle}, true)
		require.NoError(t, err)
		require.NotNil(t, importedValues)

		summaryImport := importedValues.Summary.Data().Imported
		require.EqualValues(t, 30, summaryImport.IPs)
		require.EqualValues(t, 33, summaryImport.URLs)
		require.EqualValues(t, 84, summaryImport.Domains)
		require.EqualValues(t, 0, summaryImport.Emails)

		summaryAffected := importedValues.Summary.Data().Affected
		require.EqualValues(t, 30, summaryAffected.IPs)
		require.EqualValues(t, 33, summaryAffected.URLs)
		require.EqualValues(t, 84, summaryAffected.Domains)
		require.EqualValues(t, 0, summaryAffected.Emails)

		summaryNew := importedValues.Summary.Data().New
		require.EqualValues(t, 30, summaryNew.IPs)
		require.EqualValues(t, 33, summaryNew.URLs)
		require.EqualValues(t, 84, summaryNew.Domains)
		require.EqualValues(t, 0, summaryNew.Emails)
	})

	err = clearBlacklists(t, blacklistRepo)
	require.NoError(t, err)

	err = clearBlacklists(t, blacklistRepo)
	require.NoError(t, err)

	t.Run("finCert CSV file parsing", func(t *testing.T) {
		file, err := os.Open("./files/fincert_blacklists/FinCERT_Info_20240509-153603.csv")
		require.NoError(t, err)

		csvReader := csv.NewReader(file)
		data, err := csvReader.ReadAll()
		require.NoError(t, err)
		require.NotNil(t, data)

		importedValues, err := blacklistService.ImportFromCSV(data, time.Now(), false)
		require.NoError(t, err)
		require.NotNil(t, importedValues)

		summaryImport := importedValues.Summary.Data().Imported
		require.EqualValues(t, 27, summaryImport.IPs)
		require.EqualValues(t, 33, summaryImport.URLs)
		require.EqualValues(t, 70, summaryImport.Domains)
		require.EqualValues(t, 0, summaryImport.Emails)

		summaryAffected := importedValues.Summary.Data().Affected
		require.EqualValues(t, 27, summaryAffected.IPs)
		require.EqualValues(t, 33, summaryAffected.URLs)
		require.EqualValues(t, 70, summaryAffected.Domains)
		require.EqualValues(t, 0, summaryAffected.Emails)

		summaryNew := importedValues.Summary.Data().New
		require.EqualValues(t, 27, summaryNew.IPs)
		require.EqualValues(t, 33, summaryNew.URLs)
		require.EqualValues(t, 70, summaryNew.Domains)
		require.EqualValues(t, 0, summaryNew.Emails)
	})

	err = clearBlacklists(t, blacklistRepo)
	require.NoError(t, err)

	t.Run("finCert STIX json multiple files parsing", func(t *testing.T) {
		var bundles []blacklistEntities.STIX2Bundle
		var fileNames = []string{"FinCERT_20240509-153945.json", "FinCERT_20240510-160128.json", "FinCERT_20240511-164336.json", "FinCERT_20240512-165404.json"}

		for _, fileName := range fileNames {
			var bundle blacklistEntities.STIX2Bundle

			file, err := os.ReadFile(fmt.Sprintf("./files/fincert_blacklists/%s", fileName))
			require.NoError(t, err)

			err = json.Unmarshal(file, &bundle)
			require.NoError(t, err)
			require.NotNil(t, file)

			bundles = append(bundles, bundle)
		}

		importedValues, err := blacklistService.ImportFromSTIX2(bundles, false)
		require.NoError(t, err)
		require.NotNil(t, importedValues)

		summaryImport := importedValues.Summary.Data().Imported
		require.EqualValues(t, 57, summaryImport.IPs)
		require.EqualValues(t, 101, summaryImport.URLs)
		require.EqualValues(t, 111, summaryImport.Domains)
		require.EqualValues(t, 0, summaryImport.Emails)

		summaryAffected := importedValues.Summary.Data().Affected
		require.EqualValues(t, 57, summaryAffected.IPs)
		require.EqualValues(t, 101, summaryAffected.URLs)
		require.EqualValues(t, 111, summaryAffected.Domains)
		require.EqualValues(t, 0, summaryAffected.Emails)

		summaryNew := importedValues.Summary.Data().New
		require.EqualValues(t, 57, summaryNew.IPs)
		require.EqualValues(t, 101, summaryNew.URLs)
		require.EqualValues(t, 111, summaryNew.Domains)
		require.EqualValues(t, 0, summaryNew.Emails)
	})

	err = clearBlacklists(t, blacklistRepo)
	require.NoError(t, err)

	t.Run("finCert CSV multiple files parsing", func(t *testing.T) {
		var fileNames = []string{"FinCERT_Info_20240509-153603.csv", "FinCERT_Info_20240510-155951.csv", "FinCERT_Info_20240511-164208.csv", "FinCERT_Info_20240512-165201.csv"}

		var lines [][]string

		for _, fileName := range fileNames {
			file, err := os.Open(fmt.Sprintf("./files/fincert_blacklists/%s", fileName))
			require.NoError(t, err)

			csvReader := csv.NewReader(file)
			data, err := csvReader.ReadAll()
			require.NoError(t, err)
			require.NotNil(t, data)

			lines = append(lines, data...)
		}

		importedValues, err := blacklistService.ImportFromCSV(lines, time.Now(), false)
		require.NoError(t, err)
		require.NotNil(t, importedValues)

		summaryImport := importedValues.Summary.Data().Imported
		require.EqualValues(t, 57, summaryImport.IPs)
		require.EqualValues(t, 101, summaryImport.URLs)
		require.EqualValues(t, 111, summaryImport.Domains)
		require.EqualValues(t, 0, summaryImport.Emails)

		summaryAffected := importedValues.Summary.Data().Affected
		require.EqualValues(t, 57, summaryAffected.IPs)
		require.EqualValues(t, 101, summaryAffected.URLs)
		require.EqualValues(t, 111, summaryAffected.Domains)
		require.EqualValues(t, 0, summaryAffected.Emails)

		summaryNew := importedValues.Summary.Data().New
		require.EqualValues(t, 57, summaryNew.IPs)
		require.EqualValues(t, 101, summaryNew.URLs)
		require.EqualValues(t, 111, summaryNew.Domains)
		require.EqualValues(t, 0, summaryNew.Emails)
	})
}

func clearBlacklists(t *testing.T, repo *repos.BlacklistsRepoImpl) (err error) {
	err = repo.Unscoped().Exec("DELETE FROM blacklisted_ips;").Error
	require.NoError(t, err)

	err = repo.Unscoped().Exec("DELETE FROM blacklisted_domains;").Error
	require.NoError(t, err)

	err = repo.Unscoped().Exec("DELETE FROM blacklisted_emails;").Error
	require.NoError(t, err)

	err = repo.Unscoped().Exec("DELETE FROM blacklisted_urls;").Error
	require.NoError(t, err)

	err = repo.Unscoped().Exec("DELETE FROM blacklist_import_events;").Error
	require.NoError(t, err)

	return err
}
