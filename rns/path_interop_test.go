package rns

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// path_request_upstream.json is produced by testdata/gen_path_request_upstream.py
// from upstream RNS's own Transport.parse_path_request and stamp_path_request.
type pathRequestVector struct {
	RNSVersion string  `json:"rns_version_at_generation"`
	PRCost     float64 `json:"pr_cost"`
	Cases      []struct {
		Name        string `json:"name"`
		Payload     string `json:"payload_hex"`
		Target      string `json:"target_hex"`
		TransportID string `json:"transport_id_hex"`
		Tag         string `json:"tag_hex"`
		Ext         string `json:"ext_hex"`
		StampValid  bool   `json:"stamp_valid_at_pr_cost"`
	} `json:"cases"`
}

// TestParsePathRequestMatchesUpstream pins SPEC §7.2.1: ParsePathRequest
// splits every accepted form exactly as upstream does. In particular the tag
// of a 64-byte request is bytes 32..48, not the trailing 16.
func TestParsePathRequestMatchesUpstream(t *testing.T) {
	raw, err := os.ReadFile("testdata/path_request_upstream.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v pathRequestVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("vector has no cases")
	}
	for _, c := range v.Cases {
		payload, _ := hex.DecodeString(c.Payload)
		req, err := ParsePathRequest(payload)
		if err != nil {
			t.Errorf("%s: ParsePathRequest: %v", c.Name, err)
			continue
		}
		for _, f := range []struct{ field, got, want string }{
			{"target", hex.EncodeToString(req.Target), c.Target},
			{"transport_id", hex.EncodeToString(req.TransportID), c.TransportID},
			{"tag", hex.EncodeToString(req.Tag), c.Tag},
			{"ext", hex.EncodeToString(req.Ext), c.Ext},
		} {
			if f.got != f.want {
				t.Errorf("%s: %s = %s, upstream (RNS %s) = %s", c.Name, f.field, f.got, v.RNSVersion, f.want)
			}
		}
		// Upstream stamps clear PR_COST = 15.8, so at least 15 whole bits.
		if got := req.StampValid(15); got != c.StampValid {
			t.Errorf("%s: StampValid(15) = %v, upstream validate_pr_stamp at %.1f = %v", c.Name, got, v.PRCost, c.StampValid)
		}
	}
}
