package worker

import (
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestParseFindingsOutput_minConfidenceDropsBelowThreshold(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	scan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "x", Status: db.ScanDone}
	gdb.Create(scan)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	report := `{"findings":[
		{"id":"F1","title":"a","severity":"High","cwe":"CWE-1","location":"a.rb:1","confidence":"high"},
		{"id":"F2","title":"b","severity":"High","cwe":"CWE-2","location":"b.rb:1","confidence":"low"},
		{"id":"F3","title":"c","severity":"High","cwe":"CWE-3","location":"c.rb:1"}
	]}`
	skill := &db.Skill{MinConfidence: "medium"}
	var lines []string
	emit := func(e Event) { lines = append(lines, e.Text) }

	if err := w.parseFindingsOutput(skill, scan, report, emit); err != nil {
		t.Fatal(err)
	}
	var n int64
	gdb.Model(&db.Finding{}).Count(&n)
	if n != 1 {
		t.Errorf("stored %d findings, want 1 (only high-confidence)", n)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "dropped 2 finding(s) below min_confidence=medium") {
		t.Errorf("expected drop log line, got: %s", joined)
	}
}

func TestParseFindingsOutput_failOnTriggers(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	scan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "x", Status: db.ScanDone}
	gdb.Create(scan)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	report := `{"findings":[
		{"id":"F1","title":"a","severity":"Medium","cwe":"CWE-1","location":"a.rb:1"},
		{"id":"F2","title":"b","severity":"Critical","cwe":"CWE-2","location":"b.rb:1"}
	]}`
	skill := &db.Skill{FailOn: "High"}
	err = w.parseFindingsOutput(skill, scan, report, func(Event) {})
	var fe *FailOnThresholdError
	if !errors.As(err, &fe) {
		t.Fatalf("expected FailOnThresholdError, got %v", err)
	}
	if fe.Worst != "Critical" || fe.Threshold != "High" {
		t.Errorf("error fields: %+v", fe)
	}
	var n int64
	gdb.Model(&db.Finding{}).Count(&n)
	if n != 2 {
		t.Errorf("findings should still be stored on fail_on, got %d", n)
	}
}

func TestParseFindingsOutput_failOnNoTriggerBelowThreshold(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	scan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "x", Status: db.ScanDone}
	gdb.Create(scan)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	report := `{"findings":[{"id":"F1","title":"a","severity":"Low","cwe":"CWE-1","location":"a.rb:1"}]}`
	if err := w.parseFindingsOutput(&db.Skill{FailOn: "High"}, scan, report, func(Event) {}); err != nil {
		t.Errorf("Low finding should not trigger fail_on=High: %v", err)
	}
}

func TestParseFindingsOutput_dedupesAcrossScans(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	emit := func(Event) {}

	mkScan := func(commit string) *db.Scan {
		s := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive",
			Status: db.ScanDone, Commit: commit}
		gdb.Create(s)
		return s
	}

	// Scan 1: two findings.
	report1 := `{"findings":[
		{"id":"F1","title":"SQLi in users","severity":"High","cwe":"CWE-89","location":"src/users.rb:42"},
		{"id":"F2","title":"XSS in view","severity":"Medium","cwe":"CWE-79","location":"src/view.erb:10"}
	]}`
	s1 := mkScan("abc")
	if err := w.parseFindingsOutput(&db.Skill{}, s1, report1, emit); err != nil {
		t.Fatal(err)
	}

	var after1 []db.Finding
	gdb.Order("id").Find(&after1)
	if len(after1) != 2 {
		t.Fatalf("after first scan: %d findings, want 2", len(after1))
	}
	if after1[0].SeenCount != 1 || after1[0].LastSeenScanID != s1.ID {
		t.Errorf("new finding seen-count/last-seen wrong: %+v", after1[0])
	}

	// Scan 2: F1 reappears at a different line, F2 gone, new F3.
	report2 := `{"findings":[
		{"id":"F1","title":"SQL injection in users","severity":"High","cwe":"CWE-89","location":"src/users.rb:77"},
		{"id":"F3","title":"Path traversal","severity":"High","cwe":"CWE-22","location":"src/files.rb:5"}
	]}`
	s2 := mkScan("def")
	if err := w.parseFindingsOutput(&db.Skill{}, s2, report2, emit); err != nil {
		t.Fatal(err)
	}

	var after2 []db.Finding
	gdb.Order("id").Find(&after2)
	if len(after2) != 3 {
		t.Fatalf("after second scan: %d findings, want 3 (F1 deduped, F3 new)", len(after2))
	}

	// F1 (first row) should have last-seen bumped, seen=2, but ScanID/Commit
	// (first-seen) and Title unchanged.
	f1 := after2[0]
	if f1.ScanID != s1.ID || f1.Commit != "abc" {
		t.Errorf("F1 first-seen overwritten: scan=%d commit=%q", f1.ScanID, f1.Commit)
	}
	if f1.LastSeenScanID != s2.ID || f1.LastSeenCommit != "def" || f1.SeenCount != 2 {
		t.Errorf("F1 last-seen not bumped: %+v", f1)
	}
	if f1.Title != "SQLi in users" {
		t.Errorf("F1 title overwritten by rescan: %q", f1.Title)
	}
	if f1.MissedCount != 0 {
		t.Errorf("F1 reappeared, missed count should be 0, got %d", f1.MissedCount)
	}

	// F2 did not reappear: last-seen stays at s1, missed count bumped.
	f2 := after2[1]
	if f2.LastSeenScanID != s1.ID || f2.SeenCount != 1 {
		t.Errorf("F2 last-seen should be unchanged: %+v", f2)
	}
	if f2.MissedCount != 1 || f2.LastMissedScanID != s2.ID {
		t.Errorf("F2 should be marked not-observed by s2: missed=%d last_missed=%d",
			f2.MissedCount, f2.LastMissedScanID)
	}

	// F3 is new from scan 2.
	f3 := after2[2]
	if f3.ScanID != s2.ID || f3.CWE != "CWE-22" || f3.SeenCount != 1 {
		t.Errorf("F3: %+v", f3)
	}

	// History row for the re-observation.
	var hist []db.FindingHistory
	gdb.Where("finding_id = ? AND field = ?", f1.ID, "observed").Find(&hist)
	if len(hist) != 1 || hist[0].By != "security-deep-dive" {
		t.Errorf("want one observed history row for F1, got %+v", hist)
	}
	// History row for the miss.
	var miss []db.FindingHistory
	gdb.Where("finding_id = ? AND field = ?", f2.ID, "not_observed").Find(&miss)
	if len(miss) != 1 || miss[0].By != "security-deep-dive" {
		t.Errorf("want one not_observed history row for F2, got %+v", miss)
	}
}

func TestParseFindingsOutput_preservesAnalystStatusOnReobservation(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	emit := func(Event) {}

	report := `{"findings":[{"id":"F1","title":"noise","severity":"Low","cwe":"CWE-200","location":"x.go:1"}]}`
	s1 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "semgrep", Status: db.ScanDone, Commit: "abc"}
	gdb.Create(s1)
	if err := w.parseFindingsOutput(&db.Skill{}, s1, report, emit); err != nil {
		t.Fatal(err)
	}

	// Analyst rejects it.
	gdb.Model(&db.Finding{}).Where("repository_id = ?", repo.ID).Update("status", db.FindingRejected)

	s2 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "semgrep", Status: db.ScanDone, Commit: "def"}
	gdb.Create(s2)
	if err := w.parseFindingsOutput(&db.Skill{}, s2, report, emit); err != nil {
		t.Fatal(err)
	}

	var rows []db.Finding
	gdb.Find(&rows)
	if len(rows) != 1 {
		t.Fatalf("rejected finding should still dedupe, got %d rows", len(rows))
	}
	if rows[0].Status != db.FindingRejected {
		t.Errorf("rescan must not resurrect a rejected finding: status=%s", rows[0].Status)
	}
	if rows[0].SeenCount != 2 {
		t.Errorf("seen count = %d, want 2", rows[0].SeenCount)
	}
}

func TestParseFindingsOutput_intraScanCollisionCreatesOneRow(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// Same CWE, same file, two lines: file-level fingerprint collides.
	report := `{"findings":[
		{"id":"F1","title":"a","severity":"Low","cwe":"CWE-89","location":"q.go:10"},
		{"id":"F2","title":"b","severity":"Low","cwe":"CWE-89","location":"q.go:20"}
	]}`
	s := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "k", Status: db.ScanDone, Commit: "abc"}
	gdb.Create(s)
	if err := w.parseFindingsOutput(&db.Skill{}, s, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var n int64
	gdb.Model(&db.Finding{}).Count(&n)
	if n != 1 {
		t.Errorf("intra-scan fingerprint collision should yield one row, got %d", n)
	}
	if s.FindingsCount != 2 {
		t.Errorf("scan.FindingsCount should report what the scan found (2), got %d", s.FindingsCount)
	}
}

func TestParseFindingsOutput_notObservedScopedToSkillAndSubpath(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	emit := func(Event) {}

	report := `{"findings":[{"id":"F1","title":"x","severity":"High","cwe":"CWE-89","location":"a.rb:1"}]}`

	// security-deep-dive at root finds F1.
	s1 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive",
		SubPath: "", Status: db.ScanDone, Commit: "abc"}
	gdb.Create(s1)
	if err := w.parseFindingsOutput(&db.Skill{}, s1, report, emit); err != nil {
		t.Fatal(err)
	}

	// semgrep at root finds nothing. Different skill: must not mark F1 missed.
	s2 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "semgrep",
		SubPath: "", Status: db.ScanDone, Commit: "abc"}
	gdb.Create(s2)
	if err := w.parseFindingsOutput(&db.Skill{}, s2, `{"findings":[]}`, emit); err != nil {
		t.Fatal(err)
	}

	// security-deep-dive on subpath "pkg/foo" finds nothing. Different
	// subpath: must not mark F1 missed.
	s3 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive",
		SubPath: "pkg/foo", Status: db.ScanDone, Commit: "abc"}
	gdb.Create(s3)
	if err := w.parseFindingsOutput(&db.Skill{}, s3, `{"findings":[]}`, emit); err != nil {
		t.Fatal(err)
	}

	var f db.Finding
	gdb.First(&f)
	if f.MissedCount != 0 {
		t.Errorf("out-of-scope rescans must not mark F1 missed: missed=%d", f.MissedCount)
	}

	// security-deep-dive at root finds nothing. In scope: F1 missed.
	s4 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive",
		SubPath: "", Status: db.ScanDone, Commit: "def"}
	gdb.Create(s4)
	if err := w.parseFindingsOutput(&db.Skill{}, s4, `{"findings":[]}`, emit); err != nil {
		t.Fatal(err)
	}

	gdb.First(&f)
	if f.MissedCount != 1 || f.LastMissedScanID != s4.ID {
		t.Errorf("in-scope rescan should mark F1 missed: missed=%d last_missed=%d",
			f.MissedCount, f.LastMissedScanID)
	}
}

func TestParseFindingsOutput_reobservationResetsMissedCount(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	emit := func(Event) {}

	report := `{"findings":[{"id":"F1","title":"x","severity":"High","cwe":"CWE-89","location":"a.rb:1"}]}`
	mkScan := func(commit string) *db.Scan {
		s := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive",
			Status: db.ScanDone, Commit: commit}
		gdb.Create(s)
		return s
	}

	if err := w.parseFindingsOutput(&db.Skill{}, mkScan("aaa"), report, emit); err != nil {
		t.Fatal(err)
	}
	if err := w.parseFindingsOutput(&db.Skill{}, mkScan("bbb"), `{"findings":[]}`, emit); err != nil {
		t.Fatal(err)
	}
	if err := w.parseFindingsOutput(&db.Skill{}, mkScan("ccc"), `{"findings":[]}`, emit); err != nil {
		t.Fatal(err)
	}

	var f db.Finding
	gdb.First(&f)
	if f.MissedCount != 2 {
		t.Fatalf("after two empty rescans MissedCount = %d, want 2", f.MissedCount)
	}

	// Reappears: missed count resets, seen count is now 2.
	if err := w.parseFindingsOutput(&db.Skill{}, mkScan("ddd"), report, emit); err != nil {
		t.Fatal(err)
	}
	gdb.First(&f)
	if f.MissedCount != 0 || f.LastMissedScanID != 0 {
		t.Errorf("re-observation should reset missed: missed=%d last_missed=%d",
			f.MissedCount, f.LastMissedScanID)
	}
	if f.SeenCount != 2 || f.LastSeenCommit != "ddd" {
		t.Errorf("seen=%d last_seen_commit=%q, want 2/ddd", f.SeenCount, f.LastSeenCommit)
	}
}

func TestParseFindingsOutput_notObservedSkipsClosedFindings(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	emit := func(Event) {}

	report := `{"findings":[{"id":"F1","title":"x","severity":"High","cwe":"CWE-89","location":"a.rb:1"}]}`
	s1 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "k", Status: db.ScanDone, Commit: "abc"}
	gdb.Create(s1)
	if err := w.parseFindingsOutput(&db.Skill{}, s1, report, emit); err != nil {
		t.Fatal(err)
	}
	gdb.Model(&db.Finding{}).Where("repository_id = ?", repo.ID).Update("status", db.FindingFixed)

	s2 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "k", Status: db.ScanDone, Commit: "def"}
	gdb.Create(s2)
	if err := w.parseFindingsOutput(&db.Skill{}, s2, `{"findings":[]}`, emit); err != nil {
		t.Fatal(err)
	}

	var f db.Finding
	gdb.First(&f)
	if f.MissedCount != 0 {
		t.Errorf("closed finding should not accrue missed count: missed=%d", f.MissedCount)
	}
}
