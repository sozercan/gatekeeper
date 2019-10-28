package metrics

import (
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
	TotalViolationsStat  = stats.Int64("violations_total", "Total number of violations per constraint", stats.UnitNone)
	TotalConstraintsStat = stats.Int64("constraints_total", "Total number of enforced constraints", stats.UnitNone)
)

func init() {
	views := []*view.View{{
		Name:        "violations_total",
		Measure:     TotalViolationsStat,
		Aggregation: view.LastValue(),
		TagKeys:     []tag.Key{KeyMethod},
	}, {
		Name:        "constraints_total",
		Measure:     TotalConstraintsStat,
		Aggregation: view.Count(),
		TagKeys:     []tag.Key{KeyMethod},
	}}

	if err := view.Register(views...); err != nil {
		panic(err)
	}
}
