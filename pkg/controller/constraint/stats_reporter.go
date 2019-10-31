package constraint

// import (
// 	"context"

// 	"github.com/open-policy-agent/gatekeeper/pkg/metrics"
// 	"go.opencensus.io/stats"
// 	"go.opencensus.io/stats/view"
// 	"go.opencensus.io/tag"
// )

// const (
// 	constraintsTotalName = "constraints_total"
// 	methodType           = "constraint"
// )

// var (
// 	constraintsTotalM = stats.Int64(constraintsTotalName, "Total number of enforced constraints", stats.UnitNone)

// 	methodTypeKey     = tag.MustNewKey("method_type")
// 	constraintKindKey = tag.MustNewKey("constraint_kind")
// 	constraintNameKey = tag.MustNewKey("constraint_name")
// )

// func init() {
// 	register()
// }

// func register() {
// 	tagKeys := []tag.Key{
// 		methodTypeKey,
// 		constraintKindKey,
// 		constraintNameKey}

// 	views := []*view.View{{
// 		Name:        constraintsTotalName,
// 		Measure:     constraintsTotalM,
// 		Aggregation: view.Count(),
// 		TagKeys:     tagKeys,
// 	}}

// 	if err := view.Register(views...); err != nil {
// 		panic(err)
// 	}
// }

// func (r *reporter) ReportConstraints(constraintKind, constraintName string, v int64) error {
// 	ctx, err := tag.New(
// 		r.ctx,
// 		tag.Insert(methodTypeKey, methodType),
// 		tag.Insert(constraintKindKey, constraintKind),
// 		tag.Insert(constraintNameKey, constraintName))
// 	if err != nil {
// 		return err
// 	}

// 	return r.report(ctx, constraintsTotalM.M(v))
// }

// // StatsReporter reports audit metrics
// type StatsReporter interface {
// 	ReportConstraints(constraintKind, constraintName string, v int64) error
// }

// // NewStatsReporter creaters a reporter for audit metrics
// func NewStatsReporter() (StatsReporter, error) {
// 	ctx, err := tag.New(
// 		context.Background(),
// 	)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &reporter{ctx: ctx}, nil
// }

// type reporter struct {
// 	ctx context.Context
// }

// func (r *reporter) report(ctx context.Context, m stats.Measurement) error {
// 	metrics.Record(ctx, m)
// 	return nil
// }