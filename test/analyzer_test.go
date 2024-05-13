package test

import (
	"domain_threat_intelligence_api/cmd/app"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"domain_threat_intelligence_api/cmd/core/entities/networkEntities"
	"domain_threat_intelligence_api/cmd/core/repos"
	"domain_threat_intelligence_api/cmd/core/services"
	"domain_threat_intelligence_api/configs"
	"fmt"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"testing"
	"time"
)

const host = "localhost"
const port = 50051

func TestScoringService(t *testing.T) {
	scoringService := services.NewScoringServiceImpl(host, port)

	t.Run("correct domain analysis", func(t *testing.T) {
		nodes, err := scoringService.AnalyzeNodes([]*networkEntities.NetworkNode{
			{
				Identity: "yandex.ru",
				TypeID:   2,
				Scans: []networkEntities.NetworkNodeScan{
					{
						ScanTypeID: networkEntities.SCAN_TYPE_DNS_LOOKUP,
						Data:       datatypes.JSON("{\"mx\": [\"mx.yandex.ru.\"], \"ns\": [\"ns2.yandex.ru.\", \"ns1.yandex.ru.\"], \"ips\": [\"77.88.55.242\", \"5.255.255.242\", \"2a02:6b8::2:242\"], \"ptr\": null, \"txt\": null, \"host\": \"ya.ru\", \"cname\": \"ya.ru.\", \"reverse\": {\"77.88.55.242\": [\"ya.ru.\"], \"5.255.255.242\": [\"ya.ru.\"], \"2a02:6b8::2:242\": [\"ya.ru.\"]}}"),
					},
				},
			},
		})

		require.NoError(t, err)
		require.NotEmpty(t, nodes)

		require.Equal(t, nodes[0].Scoring.Tag, networkEntities.SCORE_BENIGN)
		require.Equal(t, nodes[0].Scoring.IsMalicious, false)
		require.EqualValues(t, *nodes[0].Scoring.FinalScore, 1.0)
	})

	t.Run("invalid domain analysis (no scans)", func(t *testing.T) {
		nodes, err := scoringService.AnalyzeNodes([]*networkEntities.NetworkNode{
			{
				Identity: "yandex.ru",
				TypeID:   networkEntities.SCAN_TYPE_DNS_LOOKUP,
				Scans:    []networkEntities.NetworkNodeScan{},
			},
		})

		require.Error(t, err)
		require.NotEmpty(t, nodes)
		require.Nil(t, nodes[0].Scoring)
	})
}

func TestNetworkNodeServiceEvaluation(t *testing.T) {
	config, err := configs.NewTestConfig()
	require.NoError(t, err)

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s database=%s sslmode=disable TimeZone=%s", config.Database.Host, config.Database.Port, config.Database.User, config.Database.Password, config.Database.Name, config.Database.Timezone)
	dbConn, err := gorm.Open(postgres.Open(dsn))

	err = app.Migrate(dbConn)
	require.NoError(t, err)

	bRepo := repos.NewBlacklistsRepoImpl(dbConn)
	nRepo := repos.NewNetworkNodesRepoImpl(dbConn)

	bService := services.NewBlackListsServiceImpl(bRepo, nil)
	sService := services.NewScoringServiceImpl(host, port)

	service := services.NewNodesServiceImpl(nRepo, bService, sService)

	identity, err := service.SaveNetworkNodeWithIdentity(networkEntities.NetworkNodeScan{
		IsComplete: true,
		ScanTypeID: networkEntities.SCAN_TYPE_DNS_LOOKUP,
		RiskScore:  nil,
		JobUUID:    nil,
		Data:       datatypes.JSON("{\"mx\": [\"mx.yandex.ru.\"], \"ns\": [\"ns2.yandex.ru.\", \"ns1.yandex.ru.\"], \"ips\": [\"77.88.55.242\", \"5.255.255.242\", \"2a02:6b8::2:242\"], \"ptr\": null, \"txt\": null, \"host\": \"ya.ru\", \"cname\": \"ya.ru.\", \"reverse\": {\"77.88.55.242\": [\"ya.ru.\"], \"5.255.255.242\": [\"ya.ru.\"], \"2a02:6b8::2:242\": [\"ya.ru.\"]}}"),
		CreatedAt:  time.Time{},
		UpdatedAt:  time.Time{},
		DeletedAt:  gorm.DeletedAt{},
	}, jobEntities.Target{
		Host: "yandex.ru",
		Type: jobEntities.HOST_TYPE_DOMAIN,
	})

	if err != nil {
		return
	}

	require.NotEmpty(t, identity)
	require.NoError(t, err)

	node, err := service.EvaluateNetworkNodeScoring(identity)
	if err != nil {
		return
	}

	require.NotEmpty(t, node.Scoring)
	require.NoError(t, err)

	require.Equal(t, node.Scoring.Tag, networkEntities.SCORE_BENIGN)
	require.Equal(t, node.Scoring.IsMalicious, false)
	require.EqualValues(t, *node.Scoring.FinalScore, 1.0)
}
