# drive-audit

#Requires -RunAsAdministrator
<#
    DriveAudit.ps1 - Read-only space audit for C: (Windows 10 / 11)

    What it does:
      1. Lists installed programs on C: with their real size on disk
      2. Finds when each program was last run (from the Windows Prefetch history)
      3. Flags programs not run in the last N days (default 60)
      4. Measures the usual hidden space wasters (hibernation file, update cache, temp, etc.)
      5. Lists the biggest AppData folders (old app caches often hide here)

    NOTHING is deleted or changed. Results are saved to a folder on your Desktop.

    Run from an Administrator PowerShell:
      powershell -ExecutionPolicy Bypass -File .\DriveAudit.ps1
      powershell -ExecutionPolicy Bypass -File .\DriveAudit.ps1 -DaysUnused 90
#>
