//go:build windows

package platforminventory

import (
	"context"
	"errors"
	"koda.local/security-sbom-linux/internal/model"
	"os"
	"path/filepath"
)

const windowsScript = `$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $r=@();
Get-CimInstance Win32_ComputerSystem | ForEach-Object { $r += @{kind='device';name='Computer';identity='system';vendor=$_.Manufacturer;model=$_.Model} };
Get-CimInstance Win32_BIOS | ForEach-Object { $r += @{kind='firmware';name='BIOS';identity='bios';vendor=$_.Manufacturer;version=$_.SMBIOSBIOSVersion} };
Get-CimInstance Win32_OperatingSystem | ForEach-Object { $r += @{kind='operating-system';name=$_.Caption;identity='windows';vendor='Microsoft';version=$_.Version;build=$_.BuildNumber;architecture=$_.OSArchitecture} };
Get-CimInstance Win32_QuickFixEngineering | ForEach-Object { $r += @{kind='application';name=$_.HotFixID;identity=$_.HotFixID;hotfixId=$_.HotFixID;version=$_.HotFixID;vendor='Microsoft'} };
$paths=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*');
foreach($p in $paths) { Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object { $r += @{kind='application';name=$_.DisplayName;version=$_.DisplayVersion;vendor=$_.Publisher;identity=$_.PSPath} } };
ConvertTo-Json -InputObject @($r) -Depth 4 -Compress`

func Collect(ctx context.Context) ([]model.Asset, []model.Issue, error) {
	systemRoot := os.Getenv("SystemRoot")
	if !filepath.IsAbs(systemRoot) {
		return nil, nil, errors.New("Windows system root is unavailable")
	}
	executable := filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	raw, err := command(ctx, executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", windowsScript)
	if err != nil {
		return nil, nil, err
	}
	assets, err := parseWindows(raw)
	return assets, []model.Issue{issue("platform_scope", "Windows registry application inventory and QuickFixEngineering update inventory have limited coverage; embedded dependencies, other user profiles, Store apps and some updates require additional evidence")}, err
}
