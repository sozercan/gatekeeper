package webhook

import (
	"context"
	"strconv"
	"time"

	"github.com/open-policy-agent/gatekeeper/pkg/metrics"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
)

const (
	requestCountName     = "request_count"
	requestLatenciesName = "request_latencies"
)

var (
	requestCountM = stats.Int64(
		requestCountName,
		"The number of requests that are routed to webhook",
		stats.UnitDimensionless)
	responseTimeInMsecM = stats.Float64(
		requestLatenciesName,
		"The response time in milliseconds",
		stats.UnitMilliseconds)

	// Create the tag keys that will be used to add tags to our measurements.
	// Tag keys must conform to the restrictions described in
	// go.opencensus.io/tag/validate.go. Currently those restrictions are:
	// - length between 1 and 255 inclusive
	// - characters are printable US-ASCII
	requestOperationKey  = tag.MustNewKey("request_operation")
	kindGroupKey         = tag.MustNewKey("kind_group")
	kindVersionKey       = tag.MustNewKey("kind_version")
	kindKindKey          = tag.MustNewKey("kind_kind")
	resourceGroupKey     = tag.MustNewKey("resource_group")
	resourceVersionKey   = tag.MustNewKey("resource_version")
	resourceResourceKey  = tag.MustNewKey("resource_resource")
	resourceNameKey      = tag.MustNewKey("resource_name")
	resourceNamespaceKey = tag.MustNewKey("resource_namespace")
	admissionAllowedKey  = tag.MustNewKey("admission_allowed")
)

func init() {
	register()
}

type reporter struct {
	*metrics.Reporter
}

// StatsReporter reports webhook metrics
type StatsReporter interface {
	ReportRequest(request *admissionv1beta1.AdmissionRequest, response *admissionv1beta1.AdmissionResponse, d time.Duration) error
}

// Captures req count metric, recording the count and the duration
func (r *reporter) ReportRequest(req *admissionv1beta1.AdmissionRequest, resp *admissionv1beta1.AdmissionResponse, d time.Duration) error {
	ctx, err := tag.New(
		r.Ctx,
		tag.Insert(requestOperationKey, string(req.Operation)),
		tag.Insert(kindGroupKey, req.Kind.Group),
		tag.Insert(kindVersionKey, req.Kind.Version),
		tag.Insert(kindKindKey, req.Kind.Kind),
		tag.Insert(resourceGroupKey, req.Resource.Group),
		tag.Insert(resourceVersionKey, req.Resource.Version),
		tag.Insert(resourceResourceKey, req.Resource.Resource),
		tag.Insert(resourceNameKey, req.Name),
		tag.Insert(resourceNamespaceKey, req.Namespace),
		tag.Insert(admissionAllowedKey, strconv.FormatBool(resp.Allowed)),
	)
	if err != nil {
		return err
	}

	r.report(ctx, requestCountM.M(1))
	// Convert time.Duration in nanoseconds to milliseconds
	r.report(ctx, responseTimeInMsecM.M(float64(d/time.Millisecond)))
	return nil
}

func (r *reporter) report(ctx context.Context, m stats.Measurement) error {
	metrics.Record(ctx, m)
	return nil
}

func register() {
	tagKeys := []tag.Key{
		requestOperationKey,
		kindGroupKey,
		kindVersionKey,
		kindKindKey,
		resourceGroupKey,
		resourceVersionKey,
		resourceResourceKey,
		resourceNamespaceKey,
		resourceNameKey,
		admissionAllowedKey}

	if err := view.Register(
		&view.View{
			Description: requestCountM.Description(),
			Measure:     requestCountM,
			Aggregation: view.Count(),
			TagKeys:     tagKeys,
		},
		&view.View{
			Description: responseTimeInMsecM.Description(),
			Measure:     responseTimeInMsecM,
			Aggregation: view.Distribution(metrics.Buckets125(1, 100000)...), // [1 2 5 10 20 50 100 200 500 1000 2000 5000 10000 20000 50000 100000]ms
			TagKeys:     tagKeys,
		},
	); err != nil {
		panic(err)
	}
}
