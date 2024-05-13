package services

import (
	"context"
	"domain_threat_intelligence_api/api/grpc/protoServices"
	"domain_threat_intelligence_api/cmd/core/entities/dnsEntities"
	"domain_threat_intelligence_api/cmd/core/entities/networkEntities"
	"encoding/json"
	"errors"
	"github.com/montanaflynn/stats"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ScoringServiceImpl struct {
	analyzerClient protoServices.DomainAnalysisServiceClient
}

func NewScoringServiceImpl(host string, port uint64) *ScoringServiceImpl {
	conn, err := grpc.Dial(net.JoinHostPort(host, strconv.FormatUint(port, 10)), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		slog.Error("failed to connect to analyzer")
	}

	return &ScoringServiceImpl{analyzerClient: protoServices.NewDomainAnalysisServiceClient(conn)}
}

func (s ScoringServiceImpl) AnalyzeNodes(nodes []*networkEntities.NetworkNode) ([]*networkEntities.NetworkNode, error) {
	if s.analyzerClient == nil {
		return nil, errors.New("analyzer client not initialized")
	}

	var wg = &sync.WaitGroup{}
	wg.Add(len(nodes))

	for _, node := range nodes {
		switch node.TypeID {
		case 2: // domain
			_ = s.analyzeDomain(node, wg)
		default:
			node.Scoring = &networkEntities.NetworkNodeScoring{}

			wg.Done()
			break
		}
	}

	wg.Wait()

	return nodes, nil
}

func (s ScoringServiceImpl) analyzeDomain(node *networkEntities.NetworkNode, wg *sync.WaitGroup) error {
	if len(node.Scans) == 0 {
		return errors.New("dns resource records scans required when analyzing domain")
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(30*time.Second))
	defer cancel()
	defer wg.Done()

	semantics, resources, err := s.prepareProtoScoringPayload(*node)
	if err != nil {
		return err
	}

	sc, err := s.analyzerClient.GetFullScoring(ctx, &protoServices.FullDomainScoringParams{
		Semantics: semantics,
		Resources: resources,
		Name:      node.Identity,
	})

	if err != nil {
		return errors.New("failed to connect: " + err.Error())
	}

	now := time.Now()
	node.Scoring = &networkEntities.NetworkNodeScoring{
		DGAScore:              sc.DgaScore,
		SemanticScore:         sc.SemanticScore,
		DNSScore:              sc.ResourceScore,
		FinalScore:            sc.FinalScore,
		Tag:                   networkEntities.ScoreTag(sc.GetTag()),
		LatestScoreEvaluation: &now,
	}

	if *node.Scoring.FinalScore == 0 || node.Scoring.Tag > networkEntities.SCORE_SUSPICIOUS {
		node.Scoring.IsMalicious = true
	}

	return nil
}

func (s ScoringServiceImpl) prepareProtoScoringPayload(node networkEntities.NetworkNode) (*protoServices.SemanticData, *protoServices.ResourceRecordsData, error) {
	total, vRation, cRatio, nRatio, sRatio, pRatio, err := countSymbols(node.Identity)
	if err != nil {
		return nil, nil, err
	}

	uRatio := uniqueSymbolsRation(node.Identity)

	parts := strings.Split(node.Identity, ".")

	lCount := int64(len(parts))
	lMAD, err := levelsMAD(parts)
	if err != nil {
		return nil, nil, err
	}

	lMAD32 := float32(lMAD)

	mRepeated := maxRepeatedSymbolCount(node.Identity)

	semantics := &protoServices.SemanticData{
		LevelsCount:     &lCount,
		LevelsMAD:       &lMAD32,
		SymbolsCount:    &total,
		VowelsRatio:     &vRation,
		ConsonantsRatio: &cRatio,
		NumbersRatio:    &nRatio,
		PointsRatio:     &pRatio,
		SpecialRatio:    &sRatio,
		UniqueRatio:     &uRatio,
		MaxRepeated:     &mRepeated,
	}

	i := slices.IndexFunc(node.Scans, func(n networkEntities.NetworkNodeScan) bool {
		return n.ScanTypeID == networkEntities.SCAN_TYPE_DNS_LOOKUP
	})

	if i == -1 {
		return nil, nil, errors.New("dns resource records scan not found")
	}

	lookup := dnsEntities.DNSLookupScanBody{}
	err = json.Unmarshal(node.Scans[i].Data, &lookup)
	if err != nil {
		return nil, nil, err
	}

	resources := &protoServices.ResourceRecordsData{
		ARecords:     int64(len(lookup.IPs)),
		MxRecords:    int64(len(lookup.MailServers)),
		CnameRecords: int64(len(lookup.CanonicalName)),
		TxtRecords:   int64(len(lookup.TextRecords)),
		PtrRecords:   int64(len(lookup.PointerRecords)),
		PtrRatio:     1,
	}

	return semantics, resources, nil
}

func countSymbols(name string) (totalCount int64, vowelsRatio, consonantsRatio, numericsRatio, specialsRatio, pointsRatio float32, err error) {
	var vowelsCount, numericsCount, consonantsCount, specialsCount, pointsCount int64 = 0, 0, 0, 0, 0

	totalCount = int64(len(name))

	if totalCount == 0 {
		return 0, 0, 0, 0, 0, 0, errors.New("empty name passed")
	}

	for _, s := range name {
		switch s {
		case 'a', 'e', 'i', 'o', 'u':
			vowelsCount++
		case '1', '2', '3', '4', '5', '6', '7', '8', '9', '0':
			numericsCount++
		case 'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'y', 'z':
			consonantsCount++
		case '-', '_':
			specialsCount++
		case '.':
			pointsCount++
		default:
			return 0, 0, 0, 0, 0, 0, errors.New("empty name passed")
		}
	}

	vowelsRatio = float32(vowelsCount) / float32(totalCount)
	consonantsRatio = float32(consonantsCount) / float32(totalCount)
	numericsRatio = float32(numericsCount) / float32(totalCount)
	specialsRatio = float32(specialsCount) / float32(totalCount)
	pointsRatio = float32(pointsCount) / float32(totalCount)

	return totalCount, vowelsRatio, consonantsRatio, numericsRatio, specialsRatio, pointsRatio, nil
}

func maxRepeatedSymbolCount(name string) int64 {
	var count = 0

	for i1, v1 := range name {
		var inRow = 0

		for _, v2 := range name[i1:] {
			if v1 == v2 {
				inRow++
			} else {
				if inRow > count {
					count = inRow
				}
				break
			}
		}
	}

	return int64(count)
}

func uniqueSymbolsRation(name string) float32 {
	var unique = make(map[int32]bool)

	for _, s := range name {
		_, ok := unique[s]
		if !ok {
			unique[s] = false
		}
	}

	return float32(len(unique)) / float32(len(name))
}

func levelsMAD(parts []string) (float64, error) {
	var lengths []float64

	for _, p := range parts {
		lengths = append(lengths, float64(len(p)))
	}

	slices.Sort(lengths)

	return stats.MedianAbsoluteDeviation(lengths)
}
