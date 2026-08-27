package kurtosisenv

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// fetchPeerIDHTTP is the default peerIDFetcher: GET
// /eth/v1/node/identity and read data.peer_id.
func fetchPeerIDHTTP(beaconAPIURL string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	url := strings.TrimRight(beaconAPIURL, "/") + "/eth/v1/node/identity"
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("identity request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("identity endpoint returned %d", resp.StatusCode)
	}
	var body struct {
		Data struct {
			PeerID string `json:"peer_id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decode identity: %w", err)
	}
	return body.Data.PeerID, nil
}
