# Native platform observations

`Collect(ctx)` provides bounded observations from system tools already installed on the target platform. It uses fixed command arguments and a 60-second deadline per command, with a 32 MiB output limit. Data fields are selected before output to the SBOM. Serial numbers, UUIDs, usernames and full application paths are omitted. Local paths contribute only to hashed component identity.

On macOS the collector invokes `/usr/sbin/system_profiler` for hardware, software and application metadata. System firmware, OS loader, CPU and applications are emitted. OS build is retained in the OS version string. Application version and metadata may be unavailable for some applications.

On Windows the collector invokes system PowerShell without profiles and reads CIM computer/BIOS/OS/QuickFixEngineering records and machine/current-user uninstall registry entries. OS build and architecture are preserved. QuickFixEngineering covers only its reported updates. Registry inventory does not enumerate every user profile, Store application or embedded dependency. The collector records a coverage issue for these limits.

Native macOS verification can be run with `KODA_TEST_NATIVE_PLATFORM=1 go test -v ./internal/platforminventory`. Windows parsing fixtures and cross-compilation verify the source shape. Actual Windows execution requires a Windows target.
