package web

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

const deepDiveReport = `{
  "boundaries":[{"actor":"library caller","trusted":"yes","controls":"all parameters","source":"README.md:1"}],
  "inventory":[{"id":"S1","location":"lib/x.rb:7","class":"Command execution","consumes":"argv"}]
}`

const threatModelReport = `{
  "spec_version":1,
  "description":"Sample compressor library.",
  "components":[{"name":"core","entry_points":["inflate"],"touches":[],"in_scope":true,"provenance":"inferred"}],
  "trust_boundaries":[{"component":"core","boundary":"public API surface","reachability_precondition":"reachable from input bytes","provenance":"inferred"}],
  "entry_points":[{"entry_point":"gzopen","parameter":"path","attacker_controllable":"no","caller_must_enforce":"sanitise path","provenance":"documented","source":"zlib.h:1400"}],
  "adversaries":{"in_scope":["input supplier"],"out_of_scope":["host process"],"provenance":"inferred"},
  "properties_provided":[{"property":"memory safety on bounded input","violation_symptom":"OOB write","severity_tier":"security","provenance":"documented","source":"SECURITY.md:8"}],
  "properties_not_provided":[{"property":"bounded output size","reason":"caller's job","false_friend":false,"provenance":"inferred"}],
  "downstream_responsibilities":["cap decompressed output"],
  "known_non_findings":[{"reported_as":"strcpy in gzlib.c","why_safe":"length bounded","cites":"properties_provided[0]"}],
  "open_questions":[{"claim":"path is caller-trusted","field":"entry_points","proposed":"yes"}]
}`

func getRepoPage(t *testing.T, s *Server, id uint) string {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/repositories/%d", id)))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	return w.Body.String()
}

func TestRepoShow_threatModelTab_deepDiveOnly(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName: deepDiveSkillName, Commit: "deadbee", Report: deepDiveReport})

	body := getRepoPage(t, s, repo.ID)
	for _, want := range []string{"library caller", "all parameters", "lib/x.rb:7"} {
		if !strings.Contains(body, want) {
			t.Errorf("deep-dive-only repo page missing %q", want)
		}
	}
	if strings.Contains(body, "Entry-point trust table") {
		t.Errorf("deep-dive-only repo page rendered threat-model-skill section")
	}
}

func TestRepoShow_threatModelTab_prefersThreatModelSkill(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName: deepDiveSkillName, Commit: "deadbee", Report: deepDiveReport})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName: threatModelSkillName, Commit: "abc1234", Report: threatModelReport})

	body := getRepoPage(t, s, repo.ID)
	for _, want := range []string{
		"Sample compressor library",
		"Entry-point trust table", "gzopen", "sanitise path", "zlib.h:1400",
		"public API surface", "input supplier",
		"memory safety on bounded input", "OOB write",
		"bounded output size",
		"cap decompressed output",
		"strcpy in gzlib.c", "length bounded",
		"path is caller-trusted",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("threat-model repo page missing %q", want)
		}
	}
	for _, gone := range []string{"library caller", "lib/x.rb:7"} {
		if strings.Contains(body, gone) {
			t.Errorf("threat-model repo page still showing deep-dive content %q", gone)
		}
	}
}

func TestRepoShow_threatModelTab_fallsBackWhenSkillScanRunning(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName: deepDiveSkillName, Commit: "deadbee", Report: deepDiveReport})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanRunning,
		SkillName: threatModelSkillName, Commit: "abc1234", Report: ""})

	body := getRepoPage(t, s, repo.ID)
	if !strings.Contains(body, "library caller") {
		t.Errorf("expected fallback to deep-dive boundaries while threat-model scan is running")
	}
}
