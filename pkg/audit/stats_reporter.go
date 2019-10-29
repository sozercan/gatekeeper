package audit

import (
	"context"
	"errors"

	"github.com/open-policy-agent/gatekeeper/pkg/metrics"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
)

var (
	KeyMethod, _ = tag.NewKey("method")
	KeyStatus, _ = tag.NewKey("status")
	KeyError, _  = tag.NewKey("error")
)

var (
	TotalViolationsStat = stats.Int64("violations_total", "Total number of violations per constraint", stats.UnitNone)
	// TotalConstraintsStat = stats.Int64("constraints_total", "Total number of enforced constraints", stats.UnitNone)
)

func init() {
	views := []*view.View{{
		Name:        "violations_total",
		Measure:     TotalViolationsStat,
		Aggregation: view.LastValue(),
		TagKeys:     []tag.Key{KeyMethod, KeyStatus},
	},
	// {
	// 	Name:        "constraints_total",
	// 	Measure:     TotalConstraintsStat,
	// 	Aggregation: view.Count(),
	// 	TagKeys:     []tag.Key{KeyMethod},
	// }
	}

	if err := view.Register(views...); err != nil {
		panic(err)
	}
}

func (r *Reporter) ReportTotalViolations(constraint string, v int64) error {
	ctx, err := tag.New(
		r.ctx,
		tag.Insert(KeyMethod, "audit"),
		tag.Insert(KeyStatus, constraint))
	if err != nil {
		return err
	}

	return r.report(ctx, TotalViolationsStat.M(v))
}

type StatsReporter interface {
	ReportTotalViolations(constraint string, v int64) error
}

func NewStatsReporter() (*Reporter, error) {
	r := &Reporter{}

	ctx, err := tag.New(
		context.Background())
	if err != nil {
		return nil, err
	}

	r.ctx = ctx
	r.initialized = true
	return r, nil
}

type Reporter struct {
	ctx         context.Context
	initialized bool
}

func (r *Reporter) report(ctx context.Context, m stats.Measurement) error {
	if !r.initialized {
		return errors.New("StatsReporter is not initialized yet")
	}

	metrics.Record(ctx, m)
	return nil
}
