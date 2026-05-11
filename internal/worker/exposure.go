package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"scrutineer/internal/db"
)

// dependentCacheRoot returns the shared on-disk path scrutineer reuses
// across exposure scans of the same dependent URL. Keyed by sha256 of the
// URL so different URLs cannot collide and the path is filesystem-safe.
// The directory survives wrap()'s per-scan workspace cleanup, so the
// second exposure scan on the same dependent only fetches the delta.
func dependentCacheRoot(dataDir, url string) string {
	sum := sha256.Sum256([]byte(url))
	return filepath.Join(dataDir, "dependent-cache", hex.EncodeToString(sum[:]))
}

// doExposure runs the exposure skill for one (finding, dependent) pair.
// The scan's Repository stays the library being audited; ./src in the
// workspace is symlinked to the shared dependent cache so concurrent
// scans on different findings against the same dependent share the
// clone. The skill returns one product_status verdict that is upserted
// into finding_dependents.
func (w *Worker) doExposure(ctx context.Context, scan *db.Scan, emit func(Event)) (string, error) {
	if scan.FindingID == nil || scan.DependentID == nil {
		return "", fmt.Errorf("exposure scan %d missing finding_id or dependent_id", scan.ID)
	}
	if scan.SkillID == nil {
		return "", fmt.Errorf("exposure scan %d has no skill id", scan.ID)
	}
	var dep db.Dependent
	if err := w.DB.First(&dep, *scan.DependentID).Error; err != nil {
		return "", fmt.Errorf("load dependent %d: %w", *scan.DependentID, err)
	}
	if dep.RepositoryURL == "" {
		w.upsertExposure(scan, dep.ID, db.ExposureUnderInvestigation, "", "dependent has no repository URL", "")
		emit(Event{Kind: KindText, Text: "dependent has no repository URL; marked under_investigation"})
		return "", nil
	}
	var skill db.Skill
	if err := w.DB.First(&skill, *scan.SkillID).Error; err != nil {
		return "", fmt.Errorf("load skill %d: %w", *scan.SkillID, err)
	}
	scan.SkillName = skill.Name
	scan.SkillVersion = skill.Version
	w.DB.Model(scan).Updates(map[string]any{
		"skill_name":    skill.Name,
		"skill_version": skill.Version,
	})

	workRoot := w.workRoot(scan.ID)
	if err := validateSkillPaths(skill.Name, skill.OutputFile); err != nil {
		return "", err
	}
	if err := os.MkdirAll(workRoot, dirPerm); err != nil {
		return "", err
	}
	cache := dependentCacheRoot(w.DataDir, dep.RepositoryURL)
	if err := os.MkdirAll(cache, dirPerm); err != nil {
		return "", err
	}
	srcLink := filepath.Join(workRoot, "src")
	_ = os.Remove(srcLink)
	if err := os.Symlink(cache, srcLink); err != nil {
		return "", fmt.Errorf("symlink dependent cache: %w", err)
	}

	skillDir := filepath.Join(workRoot, ".claude", "skills", skill.Name)
	if err := stageSkill(&skill, skillDir); err != nil {
		return "", fmt.Errorf("stage skill: %w", err)
	}
	if err := stageContext(workRoot, w.APIBase, w.ForkOrg, scan, &scan.Repository); err != nil {
		return "", fmt.Errorf("stage context: %w", err)
	}

	depRepo := db.Repository{URL: dep.RepositoryURL, Name: dep.Name}
	prompt := buildSkillPrompt(skill.Name, skill.OutputFile)
	scan.Prompt = prompt
	w.DB.Model(scan).Update("prompt", prompt)

	sj := SkillJob{
		Repo:         depRepo,
		WorkRoot:     workRoot,
		Model:        scan.Model,
		Name:         skill.Name,
		SkillDir:     skillDir,
		OutputFile:   skill.OutputFile,
		Ref:          scan.Ref,
		MaxTurns:     skill.MaxTurns,
		AllowedTools: skill.AllowedTools,
	}
	res, err := w.Runner.RunSkill(ctx, sj, emit)
	scan.Commit = res.Commit
	if err != nil {
		if _, ok := errors.AsType[*MaxTurnsReachedError](err); ok && res.Report != "" {
			_ = w.parseExposureOutput(&skill, scan, dep.ID, res.Report, emit)
		}
		return res.Report, err
	}
	if res.Report != "" {
		if perr := w.parseExposureOutput(&skill, scan, dep.ID, res.Report, emit); perr != nil {
			return res.Report, perr
		}
	} else {
		w.upsertExposure(scan, dep.ID, db.ExposureUnderInvestigation, "", "skill produced no report", res.Commit)
	}
	return res.Report, nil
}

// parseExposureOutput reads the one-shot verdict produced by the exposure
// skill and upserts a finding_dependents row. Unknown status values fall
// back to under_investigation; invalid justification labels are dropped.
func (w *Worker) parseExposureOutput(skill *db.Skill, scan *db.Scan, depID uint, report string, emit func(Event)) error {
	if skill.SchemaJSON != "" {
		if detail := validateReportSchema(skill.SchemaJSON, report); detail != "" {
			emit(Event{Kind: KindError, Text: "schema: report.json does not validate against schema.json:\n" + detail})
			if w.SchemaStrict {
				return &SchemaValidationError{Skill: skill.Name, Detail: detail}
			}
		}
	}
	var r struct {
		Status        string `json:"status"`
		Justification string `json:"justification"`
		Rationale     string `json:"rationale"`
	}
	if err := json.Unmarshal([]byte(report), &r); err != nil {
		return fmt.Errorf("parse exposure report: %w", err)
	}
	if !db.ValidExposureStatus(r.Status) {
		r.Status = db.ExposureUnderInvestigation
	}
	if r.Status != db.ExposureKnownNotAffected || !db.ValidExposureJustification(r.Justification) {
		r.Justification = ""
	}
	w.upsertExposure(scan, depID, r.Status, r.Justification, r.Rationale, scan.Commit)
	emit(Event{Kind: KindText, Text: fmt.Sprintf("recorded exposure: %s", r.Status)})
	return nil
}

func (w *Worker) upsertExposure(scan *db.Scan, depID uint, status, justification, rationale, commit string) {
	row := db.FindingDependent{
		FindingID:     *scan.FindingID,
		DependentID:   depID,
		Status:        status,
		Justification: justification,
		Rationale:     rationale,
		ScanID:        &scan.ID,
		ScanCommit:    commit,
	}
	var existing db.FindingDependent
	err := w.DB.Where("finding_id = ? AND dependent_id = ?", row.FindingID, row.DependentID).First(&existing).Error
	if err != nil {
		_ = w.DB.Create(&row).Error
		return
	}
	w.DB.Model(&existing).Updates(map[string]any{
		"status":        row.Status,
		"justification": row.Justification,
		"rationale":     row.Rationale,
		"scan_id":       row.ScanID,
		"scan_commit":   row.ScanCommit,
	})
}
