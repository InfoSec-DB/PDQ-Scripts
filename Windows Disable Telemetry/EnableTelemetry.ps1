# ===========================================
# CBKB - DeadlyData
# www.colorblind.keybangers
# ===========================================
# Script Title   : Restore Default Telemetry Settings
# Description    : Restores telemetry services, tasks, and host tracking to default settings.
# ===========================================

# Initialize stats tracking
$stats = @{
    "ServicesRestored" = 0
    "ServicesFailed" = 0
    "HostsRestored" = 0
    "HostsFailed" = 0
    "TasksRestored" = 0
    "TasksFailed" = 0
    "RegistryRestored" = 0
    "RegistryFailed" = 0
}

# Suppress warnings and log internally
$ErrorActionPreference = "SilentlyContinue"
$WarningPreference = "Continue"

# Restore telemetry and tracking settings
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "CBKB - DeadlyData Cleanup Script Execution Started" -ForegroundColor Cyan
Write-Host "www.colorblind.keybangers" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan

Function Restore-Telemetry {
    Write-Host "Restoring telemetry and tracking to default settings..." -ForegroundColor Green

    try {
        # Re-enable services
        $services = @(
            "DiagTrack",
            "dmwappushsvc",
            "RetailDemo"
        )

        foreach ($service in $services) {
            Write-Host "Restoring service: ${service}" -ForegroundColor Cyan
            try {
                if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                    Set-Service -Name $service -StartupType Manual -ErrorAction SilentlyContinue
                    Start-Service -Name $service -ErrorAction SilentlyContinue
                    Write-Host "Service ${service} restored successfully." -ForegroundColor Green
                    $stats["ServicesRestored"]++
                } else {
                    Write-Warning "Service ${service} not found on this system."
                    $stats["ServicesFailed"]++
                }
            } catch {
                Write-Warning "Failed to restore service ${service}: $_"
                $stats["ServicesFailed"]++
            }
        }

        # Restore telemetry hosts
        $telemetryHosts = @(
            "vortex.data.microsoft.com",
            "settings-win.data.microsoft.com",
            "telemetry.microsoft.com",
            "oca.telemetry.microsoft.com",
            "sqm.telemetry.microsoft.com",
            "watson.telemetry.microsoft.com"
        )

        $hostsFile = "C:\Windows\System32\drivers\etc\hosts"

        try {
            $originalHosts = Get-Content $hostsFile | Where-Object { $_ -notmatch "0\.0\.0\.0\s+(${([regex]::Escape($telemetryHosts -join '|'))})" }
            Set-Content -Path $hostsFile -Value $originalHosts
            Write-Host "Telemetry hosts restored successfully." -ForegroundColor Green
            $stats["HostsRestored"] = $telemetryHosts.Count
        } catch {
            Write-Warning "Failed to restore telemetry hosts: $_"
            $stats["HostsFailed"] = $telemetryHosts.Count
        }

        # Re-enable scheduled tasks
        $tasks = @(
            "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
            "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
            "\Microsoft\Windows\Application Experience\StartupAppTask",
            "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
            "\Microsoft\Windows\Customer Experience Improvement Program\Uploader",
            "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
            "\Microsoft\Windows\Feedback\SIUF\DmClient",
            "\Microsoft\Windows\Feedback\SIUF\DmClientOnScenarioDownload"
        )

        foreach ($task in $tasks) {
            Write-Host "Re-enabling scheduled task: ${task}" -ForegroundColor Cyan
            try {
                schtasks /Change /TN $task /Enable 2>$null
                Write-Host "Task ${task} restored successfully." -ForegroundColor Green
                $stats["TasksRestored"]++
            } catch {
                Write-Warning "Failed to restore task ${task}: $_"
                $stats["TasksFailed"]++
            }
        }

        # Restore registry settings
        $registryKeys = @(
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        )

        foreach ($key in $registryKeys) {
            Write-Host "Removing registry key: ${key}" -ForegroundColor Cyan
            try {
                if (Test-Path $key) {
                    Remove-Item -Path $key -Recurse -Force
                    Write-Host "Registry key ${key} removed successfully." -ForegroundColor Green
                    $stats["RegistryRestored"]++
                } else {
                    Write-Host "Registry key ${key} does not exist. Skipping." -ForegroundColor Yellow
                }
            } catch {
                Write-Warning "Failed to remove registry key ${key}: $_"
                $stats["RegistryFailed"]++
            }
        }
    } catch {
        Write-Error "An error occurred while restoring telemetry: $_"
        exit 1
    }
}

# Call the restore function
Restore-Telemetry

# Stats Summary
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "CBKB - DeadlyData Cleanup Script Execution Complete" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "Services Restored: $($stats.ServicesRestored)"
Write-Host "Services Failed: $($stats.ServicesFailed)"
Write-Host "Hosts Restored: $($stats.HostsRestored)"
Write-Host "Hosts Failed: $($stats.HostsFailed)"
Write-Host "Tasks Restored: $($stats.TasksRestored)"
Write-Host "Tasks Failed: $($stats.TasksFailed)"
Write-Host "Registry Keys Restored: $($stats.RegistryRestored)"
Write-Host "Registry Keys Failed: $($stats.RegistryFailed)"

# Explicit success exit for PDQ Deploy
exit 0
