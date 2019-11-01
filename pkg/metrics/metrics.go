package metrics

import (
	"context"

	"go.opencensus.io/tag"
)

// NewStatsReporter creaters a reporter for audit metrics
func NewStatsReporter() (StatsReporter, error) {
	ctx, err := tag.New(
		context.Background(),
	)
	if err != nil {
		return nil, err
	}

	return &Reporter{Ctx: ctx}, nil
}

type Reporter struct {
	Ctx context.Context
}

type StatsReporter interface{}
