//go:build darwin

package platforminventory

import (
	"context"
	"koda.local/security-sbom-linux/internal/model"
)

func Collect(ctx context.Context) ([]model.Asset, []model.Issue, error) {
	raw, err := command(ctx, "/usr/sbin/system_profiler", "SPHardwareDataType", "SPSoftwareDataType", "-json")
	if err != nil {
		return nil, nil, err
	}
	assets, err := parseMac(raw)
	if err != nil {
		return nil, nil, err
	}
	issues := []model.Issue{issue("platform_scope", "Native inventory covers system firmware and application metadata; embedded dependencies and device firmware require additional evidence")}
	raw, err = command(ctx, "/usr/sbin/system_profiler", "SPApplicationsDataType", "-json")
	if err != nil {
		issues = append(issues, issue("applications_unavailable", "Application inventory could not be collected"))
		return assets, issues, nil
	}
	apps, err := parseMac(raw)
	if err != nil {
		issues = append(issues, issue("applications_unavailable", "Application inventory was incomplete"))
		return assets, issues, nil
	}
	return append(assets, apps...), issues, nil
}
