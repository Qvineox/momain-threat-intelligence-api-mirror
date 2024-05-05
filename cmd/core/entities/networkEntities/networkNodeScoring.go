package networkEntities

import (
	"time"
)

type NetworkNodeScoring struct {
	DGAScore              *float32   `json:"DGAScore"`
	SemanticScore         *float32   `json:"SemanticScore"`
	DNSScore              *float32   `json:"DNSScore"`
	OverallScore          *float32   `json:"OverallScore"`
	IsMalicious           bool       `json:"IsMalicious"`
	Tag                   ScoreTag   `json:"Tag"`
	LatestScoreEvaluation *time.Time `json:"LatestScoreEvaluation"`
}

type ScoreTag uint64

const (
	SCORE_BENIGN     ScoreTag = iota
	SCORE_DUBIOUS             = 1
	SCORE_SUSPICIOUS          = 2
	SCORE_MALICIOUS           = 3
)
