package constrainttemplate

const (
	// ErrCreateCode indicates a problem creating a ConstraintTemplate CRD.
	ErrCreateCode = "create_error"
	// ErrUpdateCode indicates a problem updating a ConstraintTemplate CRD.
	ErrUpdateCode = "update_error"
	// ErrConversionCode indicates a problem converting a ConstraintTemplate CRD.
	ErrConversionCode = "conversion_error"
	// ErrIngestCode indicates a problem ingesting a ConstraintTemplate Rego code.
	ErrIngestCode = "ingest_error"
	// VapGenerationLabel indicates opting in and out preference for generating VAP objects
	VapGenerationLabel = "gatekeeper.sh/use-vap"
	// VapFlagNone:do not generate
	VapFlagNone = "NONE"
	// VapFlagGatekeeperDefault:do not generate unless label gatekeeper.sh/use-vap: yes is added to policy explictly
	VapFlagGatekeeperDefault = "GATEKEEPER_DEFAULT"
	// VapFlagVapDefault: generate unless label gatekeeper.sh/use-vap: no is added to policy explictly
	VapFlagVapDefault = "VAP_DEFAULT"
)
