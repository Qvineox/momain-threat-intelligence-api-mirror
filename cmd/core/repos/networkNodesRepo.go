package repos

import (
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"domain_threat_intelligence_api/cmd/core/entities/networkEntities"
	"github.com/jackc/pgtype"
	"gorm.io/gorm"
	"log/slog"
	"time"
)

type NetworkNodesRepoImpl struct {
	*gorm.DB
}

func NewNetworkNodesRepoImpl(DB *gorm.DB) *NetworkNodesRepoImpl {
	return &NetworkNodesRepoImpl{DB: DB}
}

func (r NetworkNodesRepoImpl) SelectOrCreateByTarget(target jobEntities.Target) (networkEntities.NetworkNode, error) {
	node := networkEntities.NetworkNode{}
	now := time.Now()

	err := r.
		Where("identity = ? AND type_id = ?", target.Host, target.Type+1).
		Attrs(networkEntities.NetworkNode{
			Identity:     target.Host,
			DiscoveredAt: &now,
			TypeID:       uint64(target.Type + 1),
		}).
		FirstOrCreate(&node).Error

	return node, err
}

func (r NetworkNodesRepoImpl) SelectNetworkNodesByFilter(filter networkEntities.NetworkNodeSearchFilter) ([]networkEntities.NetworkNode, error) {
	query := r.Model(&networkEntities.NetworkNode{})

	if filter.CreatedAfter != nil {
		query = query.Where("created_at > ?", filter.CreatedAfter)
	}

	if filter.CreatedBefore != nil {
		query = query.Where("created_at < ?", filter.CreatedBefore)
	}

	if filter.DiscoveredAfter != nil {
		query = query.Where("discovered_at > ?", filter.DiscoveredAfter)
	}

	if filter.DiscoveredBefore != nil {
		query = query.Where("discovered_at < ?", filter.DiscoveredBefore)
	}

	if len(filter.SearchString) > 0 {
		query = query.Where("identity LIKE ?", "%"+filter.SearchString+"%")
	}

	if len(filter.TypeIDs) > 0 {
		query = query.Where("type_id IN ?", filter.TypeIDs)
	}

	if filter.Limit != 0 {
		query = query.Limit(filter.Limit)
	}

	nodes := make([]networkEntities.NetworkNode, 0)
	err := query.Offset(filter.Offset).Order("created_at DESC, updated_at DESC, UUID DESC").Find(&nodes).Error

	return nodes, err
}

func (r NetworkNodesRepoImpl) SaveNetworkNode(node networkEntities.NetworkNode) (networkEntities.NetworkNode, error) {
	err := r.Save(&node).Error

	return node, err
}

func (r NetworkNodesRepoImpl) DeleteNetworkNode(uuid pgtype.UUID) (int64, error) {
	query := r.Where("UUID = ?", uuid).Delete(&networkEntities.NetworkNode{})

	return query.RowsAffected, query.Error
}

func (r NetworkNodesRepoImpl) SaveNetworkNodeScan(scan networkEntities.NetworkNodeScan) (networkEntities.NetworkNodeScan, error) {
	err := r.Save(&scan).Error

	return scan, err
}

func (r NetworkNodesRepoImpl) CreateNetworkNodeWithIdentity(scan networkEntities.NetworkNodeScan, target jobEntities.Target) (pgtype.UUID, error) {
	node, err := r.SelectOrCreateByTarget(target)
	if err != nil {
		return pgtype.UUID{}, err
	}

	scan.NodeUUID = node.UUID

	_, err = r.SaveNetworkNodeScan(scan)
	return scan.NodeUUID, err
}

func (r NetworkNodesRepoImpl) SelectNetworkNodeByUUID(uuid pgtype.UUID) (networkEntities.NetworkNode, error) {
	node := networkEntities.NetworkNode{}

	err := r.Preload("Type").Find(&node, uuid).Error
	if err != nil {
		return networkEntities.NetworkNode{}, err
	}

	node.Scans, err = r.selectLatestScansByNodeUUID(node.UUID)
	if err != nil {
		slog.Warn("failed to query latest node scans: " + err.Error())
	}

	return node, nil
}

func (r NetworkNodesRepoImpl) selectLatestScansByNodeUUID(uuid pgtype.UUID) ([]networkEntities.NetworkNodeScan, error) {
	scans := make([]networkEntities.NetworkNodeScan, 0)

	err := r.Raw("SELECT DISTINCT ON (scan_type_id) * "+
		"FROM network_node_scans WHERE node_uuid = ? AND is_complete = true "+
		"ORDER BY scan_type_id, created_at DESC;", uuid).Scan(&scans).Error

	return scans, err
}
