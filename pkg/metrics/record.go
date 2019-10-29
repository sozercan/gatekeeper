package metrics

import (
	"context"

	"go.opencensus.io/stats"
)

func Record(ctx context.Context, ms stats.Measurement, ros ...stats.Options) {
	ros = append(ros, stats.WithMeasurements(ms))

	stats.RecordWithOptions(ctx, ros...)
}

// Buckets125 generates an array of buckets with approximate powers-of-two
// buckets that also aligns with powers of 10 on every 3rd step. This can
// be used to create a view.Distribution.
func Buckets125(low, high float64) []float64 {
	buckets := []float64{low}
	for last := low; last < high; last = last * 10 {
		buckets = append(buckets, 2*last, 5*last, 10*last)
	}
	return buckets
}
