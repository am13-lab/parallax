package kurtosisenv

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kurtosis-tech/kurtosis/api/golang/core/lib/enclaves"
	"github.com/kurtosis-tech/kurtosis/api/golang/core/lib/services"
	"github.com/kurtosis-tech/kurtosis/api/golang/core/lib/starlark_run_config"
	kurtosis_context "github.com/kurtosis-tech/kurtosis/api/golang/engine/lib/kurtosis_context"
)

// ethereumPackageWrapper runs the ethereum-package from a Starlark script,
// mirroring `kurtosis run github.com/ethpandaops/ethereum-package --args-file`.
const ethereumPackageWrapper = `def run(plan, args):
    run("github.com/ethpandaops/ethereum-package", args)
`

// RealClient talks to a local kurtosis engine over the Go API. The mapping
// logic is fake-tested; live behavior is manual-verified against a running
// engine, per the design doc.
type RealClient struct {
	ctx    *kurtosis_context.KurtosisContext
	packageID string
}

// NewRealClient connects to the local kurtosis engine.
func NewRealClient() (*RealClient, error) {
	ctx, err := kurtosis_context.NewKurtosisContextFromLocalEngine()
	if err != nil {
		return nil, fmt.Errorf("connect to kurtosis engine: %w", err)
	}
	return &RealClient{ctx: ctx, packageID: "github.com/ethpandaops/ethereum-package"}, nil
}

// ListCLServices enumerates CL services in the enclave and extracts the
// port bindings the mapping needs.
func (r *RealClient) ListCLServices(ctx context.Context, enclave string) ([]ServiceInfo, error) {
	enclaveCtx, err := r.ctx.GetEnclaveContext(ctx, enclave)
	if err != nil {
		return nil, fmt.Errorf("get enclave %s: %w", enclave, err)
	}
	serviceCtxs, err := enclaveCtx.GetServiceContexts(nil)
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}

	var out []ServiceInfo
	for name, svcCtx := range serviceCtxs {
		nameStr := string(name)
		if !strings.HasPrefix(nameStr, "cl-") {
			continue
		}
		info := ServiceInfo{
			Name:     nameStr,
			PublicIP: svcCtx.GetMaybePublicIPAddress(),
			Ports:    map[string]uint16{},
		}
		for portName, spec := range svcCtx.GetPublicPorts() {
			info.Ports[portName] = spec.GetNumber()
		}
		out = append(out, info)
	}
	return out, nil
}

// Logs streams service logs since the given time into a slice.
func (r *RealClient) Logs(ctx context.Context, enclave, service string, since time.Time) ([]string, error) {
	enclaveCtx, err := r.ctx.GetEnclaveContext(ctx, enclave)
	if err != nil {
		return nil, err
	}
	serviceCtx, err := enclaveCtx.GetServiceContext(service)
	if err != nil {
		return nil, fmt.Errorf("service %s: %w", service, err)
	}
	logsChan, cancel, err := r.ctx.GetServiceLogs(
		ctx,
		enclave,
		map[services.ServiceUUID]bool{serviceCtx.GetServiceUUID(): true},
		false, // follow
		false, // returnAll
		0,     // numLogLines
		nil,   // filter
	)
	if err != nil {
		return nil, fmt.Errorf("get logs for %s: %w", service, err)
	}
	defer cancel()

	var lines []string
	for {
		select {
		case <-ctx.Done():
			return lines, nil
		case content, ok := <-logsChan:
			if !ok {
				return lines, nil
			}
			// The kurtosis log stream carries no per-line timestamps in
			// v1.20, so `since` cannot filter here; callers pre-position
			// by requesting logs at test boundaries instead.
			for _, serviceLogs := range content.GetServiceLogsByServiceUuids() {
				for _, logLine := range serviceLogs {
					lines = append(lines, logLine.GetContent())
				}
			}
		}
	}
}

// Provision creates the enclave and runs ethereum-package with the args file.
func (r *RealClient) Provision(ctx context.Context, enclaveName, argsFile string) error {
	argsData, err := os.ReadFile(argsFile)
	if err != nil {
		return fmt.Errorf("read args file %s: %w", argsFile, err)
	}

	_, err = r.ctx.CreateEnclave(ctx, enclaveName)
	if err != nil {
		// An existing enclave of the same name is fine: run against it.
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("create enclave %s: %w", enclaveName, err)
		}
	}
	enclaveCtx, err := r.ctx.GetEnclaveContext(ctx, enclaveName)
	if err != nil {
		return fmt.Errorf("get enclave %s: %w", enclaveName, err)
	}

	runConfig := starlark_run_config.NewRunStarlarkConfig(
		starlark_run_config.WithSerializedParams(string(argsData)),
		starlark_run_config.WithParallel(true),
	)
	_, err = enclaveCtx.RunStarlarkScriptBlocking(ctx, ethereumPackageWrapper, runConfig)
	if err != nil {
		return fmt.Errorf("run %s: %w", r.packageID, err)
	}
	return nil
}

// Destroy removes the enclave.
func (r *RealClient) Destroy(ctx context.Context, enclaveName string) error {
	return r.ctx.DestroyEnclave(ctx, enclaveName)
}

// Compile-time interface check.
var _ APIClient = (*RealClient)(nil)
var _ = enclaves.EnclaveContext{}
