// Command hive-sim is an ethereum/hive simulator that runs the
// parallax engine against hive-launched consensus clients.
//
// V1 scope (per DESIGN.md): suite construction, client orchestration and
// result mapping, tested against a fake hive API. Genesis and bootnode
// provisioning for six real CL clients under hive's HIVE_* conventions is
// documented as future work.
package main

import (
	"os"
	"strings"

	"github.com/ethereum/hive/hivesim"
)

func main() {
	cfg := ConfigFromEnv()
	suite := BuildSuite(cfg)
	hivesim.MustRunSuite(hivesim.New(), suite)
}

// ConfigFromEnv reads the simulator configuration from environment
// variables: HIVE_DF_CLIENTS (comma-separated CL client types) and
// HIVE_DF_CATEGORIES (optional category filter).
func ConfigFromEnv() Config {
	clientTypes := []string{"prysm", "lighthouse", "teku", "nimbus", "lodestar", "grandine"}
	if v := os.Getenv("HIVE_DF_CLIENTS"); v != "" {
		clientTypes = nil
		for _, c := range strings.Split(v, ",") {
			if c = strings.TrimSpace(c); c != "" {
				clientTypes = append(clientTypes, c)
			}
		}
	}
	var categories []string
	if v := os.Getenv("HIVE_DF_CATEGORIES"); v != "" {
		for _, c := range strings.Split(v, ",") {
			if c = strings.TrimSpace(c); c != "" {
				categories = append(categories, c)
			}
		}
	}
	return Config{
		ClientTypes: clientTypes,
		Categories:  categories,
		HTTPPort:    DefaultHTTPPort,
		P2PPort:     9000,
	}
}
