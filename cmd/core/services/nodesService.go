package services

import (
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/blacklistEntities"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"domain_threat_intelligence_api/cmd/core/entities/networkEntities"
	"errors"
	"github.com/jackc/pgtype"
	"log/slog"
)

type NodesServiceImpl struct {
	nodesRepo core.INetworkNodesRepo

	blacklists core.IBlacklistsService
	scoring    core.IScoringService
}

func NewNodesServiceImpl(repo core.INetworkNodesRepo, blacklists core.IBlacklistsService, scoring core.IScoringService) *NodesServiceImpl {
	return &NodesServiceImpl{nodesRepo: repo, blacklists: blacklists, scoring: scoring}
}

func (n NodesServiceImpl) RetrieveNetworkNodeByUUID(uuid pgtype.UUID) (networkEntities.NetworkNode, error) {
	node, err := n.nodesRepo.SelectNetworkNodeByUUID(uuid)
	if err != nil {
		return networkEntities.NetworkNode{}, err
	} else if node.UUID.Status == pgtype.Undefined {
		return networkEntities.NetworkNode{}, nil
	}

	node.Profile = networkEntities.NewNetworkNodeProfile(node.Identity, node.TypeID)

	// checking is node identity in blacklists
	blacklists, err := n.blacklists.RetrieveHostsByFilter(blacklistEntities.BlacklistSearchFilter{
		Limit:        10,
		SearchString: node.Identity,
	})

	if err != nil {
		slog.Error("failed to retrieve blacklists on node: " + node.Identity)
	} else {
		node.Profile.WithBlacklisted(len(blacklists) > 0)
	}

	node.Profile = node.Profile.WithNodeScans(node.Scans)

	return node, nil
}

func (n NodesServiceImpl) RetrieveNetworkNodesByFilter(filter networkEntities.NetworkNodeSearchFilter) ([]networkEntities.NetworkNode, error) {
	return n.nodesRepo.SelectNetworkNodesByFilter(filter)
}

func (n NodesServiceImpl) SaveNetworkNode(node networkEntities.NetworkNode) (networkEntities.NetworkNode, error) {
	return n.nodesRepo.SaveNetworkNode(node)
}

func (n NodesServiceImpl) SaveNetworkNodeWithIdentity(scan networkEntities.NetworkNodeScan, target jobEntities.Target) (pgtype.UUID, error) {
	return n.nodesRepo.CreateNetworkNodeWithIdentity(scan, target)
}

func (n NodesServiceImpl) DeleteNetworkNode(uuid pgtype.UUID) (int64, error) {
	return n.nodesRepo.DeleteNetworkNode(uuid)
}

func (n NodesServiceImpl) EvaluateNetworkNodeScoring(uuid pgtype.UUID) (networkEntities.NetworkNode, error) {
	node, err := n.nodesRepo.SelectNetworkNodeByUUID(uuid)
	if err != nil {
		return networkEntities.NetworkNode{}, err
	} else if node.UUID.Status == pgtype.Undefined {
		return networkEntities.NetworkNode{}, errors.New("node not found")
	}

	nodes, err := n.scoring.AnalyzeNodes([]*networkEntities.NetworkNode{&node})
	if err != nil {
		return networkEntities.NetworkNode{}, err
	} else if len(nodes) != 1 {
		return networkEntities.NetworkNode{}, errors.New("multiple nodes returned from analyser")
	}

	node, err = n.nodesRepo.SaveNetworkNode(*nodes[0])
	if err != nil {
		return networkEntities.NetworkNode{}, err
	}

	return node, nil
}
