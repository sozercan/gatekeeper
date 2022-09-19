package wasm

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"

	constraints2 "github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	target2 "github.com/open-policy-agent/gatekeeper/pkg/target"
	"github.com/open-policy-agent/opa/storage"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func NewDriver() *Driver {
	return &Driver{
		wasmModules: make(map[string]string),
	}
}

type Driver struct {
	wasmModules map[string]string
}

type wasmDecision struct {
	Decision       bool
	ConstraintName string
}

var _ drivers.Driver = &Driver{}

func (d *Driver) AddTemplate(ctx context.Context, ct *templates.ConstraintTemplate) error {

	if len(ct.Spec.Targets) == 0 {
		return nil
	}

	wasmCode := ct.Spec.Targets[0].Rego //Wasm
	if wasmCode == "" {
		return nil
	}
	/// TODO: let's pretend this is just a string for now
	d.wasmModules[ct.Name] = wasmCode
	return nil
}

func (d *Driver) RemoveTemplate(ctx context.Context, ct *templates.ConstraintTemplate) error {
	delete(d.wasmModules, ct.Name)

	return nil
}

func (d *Driver) AddConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	wasmModuleName := strings.ToLower(constraint.GetKind())

	_, found := d.wasmModules[wasmModuleName]
	if !found {
		return fmt.Errorf("no wasmModuleName with name: %q", wasmModuleName)
	}

	return nil
}

func (d *Driver) RemoveConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	return nil
}

func (d *Driver) AddData(ctx context.Context, target string, path storage.Path, data interface{}) error {
	return nil
}

func (d *Driver) RemoveData(ctx context.Context, target string, path storage.Path) error {
	return nil
}

func (d *Driver) Query(ctx context.Context, target string, constraints []*unstructured.Unstructured, review interface{}, opts ...drivers.QueryOpt) ([]*types.Result, *string, error) {

	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)
	_, err := r.NewModuleBuilder("env").
		//ExportFunction("log", "logString").
		Instantiate(ctx, r)
	if err != nil {
		return nil, nil, err
	}
	// TinyGo needs wasi to
	// implement functions such as panic.
	// Need to see if we absolutely need it later
	if _, err = wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		return nil, nil, err
	}

	wasmModuleName := make(map[string]bool)
	// only run the constraints with wasm modules
	for _, constraint := range constraints {
		wasmModuleName[strings.ToLower(constraint.GetKind())] = true
	}

	gkr := review.(*target2.GkReview)

	obj := &unstructured.Unstructured{
		Object: make(map[string]interface{}),
	}

	err = obj.UnmarshalJSON(gkr.Object.Raw)
	if err != nil {
		return nil, nil, err
	}

	resource := map[string]interface{}{
		"resource": obj.Object,
	}
	var allDecisions []wasmDecision
	for name := range wasmModuleName {
		wasmModule, found := d.wasmModules[name]
		if !found {
			continue
		}

		fmt.Println("Running wasm module", name)
		mod, err := r.InstantiateModuleFromBinary(ctx, []byte(wasmModule))
		if err != nil {
			return nil, nil, err
		}
		modEval := mod.ExportedFunction("eval")

		resourceSize := uint64(len(resource))
		decision, err := modEval.Call(ctx, resourceSize)
		if err != nil {
			return nil, nil, fmt.Errorf("error running wasm module eval: %v", err)
		}

		ptr := uint32(decision[0] >> 32)
		size := uint32(decision[0])

		var d bool
		if bytes, ok := mod.Memory().Read(ctx, ptr, size); !ok {
			log.Panicf("Memory.Read(%d, %d) out of range of memory size %d",
				ptr, size, mod.Memory().Size(ctx))
		} else {
			fmt.Println("go >>", string(bytes))
			d, _ = strconv.ParseBool(string(bytes))
		}

		wasmDecision := &wasmDecision{
			Decision:       d,
			ConstraintName: name,
		}

		allDecisions = append(allDecisions, *wasmDecision)
	}
	if len(allDecisions) == 0 {
		return nil, nil, nil
	}

	results := make([]*types.Result, len(allDecisions))
	for i, wasmDecision := range allDecisions {
		results[i] = &types.Result{
			Metadata: map[string]interface{}{
				"name": wasmDecision.ConstraintName,
			},
			Constraint:        constraints[0],
			Msg:               wasmDecision.ConstraintName,
			EnforcementAction: constraints2.EnforcementActionDeny,
		}
	}

	return results, nil, nil
}

func (d *Driver) Dump(ctx context.Context) (string, error) {
	//TODO implement me
	panic("implement me")
}
