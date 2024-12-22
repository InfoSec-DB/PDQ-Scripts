# ===========================================
# CBKB - DeadlyData
# www.colorblind.keybangers
# ===========================================
# Script Title   : Disable Windows Telemetry
# Description    : Disables telemetry services, tasks, and host tracking for Windows 10/11/Server.
# ===========================================

# Initialize stats tracking
$stats = @{
    "ServicesDisabled" = 0
    "ServicesFailed" = 0
    "HostsBlocked" = 0
    "HostsFailed" = 0
    "TasksDisabled" = 0
    "TasksFailed" = 0
    "RegistryUpdated" = 0
    "RegistryFailed" = 0
}

# Suppress warnings and log internally
$ErrorActionPreference = "SilentlyContinue"
$WarningPreference = "Continue"

# Detect OS version and architecture
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "CBKB - DeadlyData Script Execution Started" -ForegroundColor Cyan
Write-Host "www.colorblind.keybangers" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan

Write-Host "Detecting system architecture and OS version..." -ForegroundColor Green

try {
    $OSVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Version
    $Architecture = (Get-CimInstance -ClassName Win32_Processor).AddressWidth

    Write-Host "OS Version: $OSVersion" -ForegroundColor Yellow
    Write-Host "Architecture: $Architecture-bit" -ForegroundColor Yellow
} catch {
    Write-Error "Failed to detect OS version or architecture: $_"
    exit 1
}

# Disable telemetry for Windows 10/11/Server
Write-Host "Disabling telemetry and tracking..." -ForegroundColor Green

Function Disable-Telemetry {
    Write-Host "Executing telemetry and tracking disabling commands..." -ForegroundColor Cyan

    try {
        # Disable services
        $services = @(
            "DiagTrack",
            "dmwappushsvc",
            "RetailDemo"
        )

        foreach ($service in $services) {
            Write-Host "Attempting to disable service: ${service}" -ForegroundColor Cyan
            try {
                if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $service -StartupType Disabled
                    Write-Host "Service ${service} disabled successfully." -ForegroundColor Green
                    $stats["ServicesDisabled"]++
                } else {
                    Write-Warning "Service ${service} not found on this system."
                    $stats["ServicesFailed"]++
                }
            } catch {
                Write-Warning "Failed to disable service ${service}: $_"
                $stats["ServicesFailed"]++
            }
        }

        # Block telemetry hosts
        $telemetryHosts = @(
            "vortex.data.microsoft.com",
            "settings-win.data.microsoft.com",
            "telemetry.microsoft.com",
            "oca.telemetry.microsoft.com",
            "sqm.telemetry.microsoft.com",
            "watson.telemetry.microsoft.com"
        )

        $hostsFile = "C:\Windows\System32\drivers\etc\hosts"

        foreach ($telemetryHost in $telemetryHosts) {
            try {
                if (-not (Select-String -Path $hostsFile -Pattern $telemetryHost -Quiet)) {
                    Write-Host "Blocking telemetry host: ${telemetryHost}" -ForegroundColor Cyan
                    Add-Content -Path $hostsFile -Value "0.0.0.0 ${telemetryHost}"
                    $stats["HostsBlocked"]++
                } else {
                    Write-Host "Host ${telemetryHost} is already blocked." -ForegroundColor Yellow
                }
            } catch {
                Write-Warning "Failed to block telemetry host ${telemetryHost}: $_"
                $stats["HostsFailed"]++
            }
        }

        # Disable scheduled tasks
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
            try {
                Write-Host "Disabling scheduled task: ${task}" -ForegroundColor Cyan
                schtasks /Change /TN $task /Disable 2>$null
                Write-Host "Task ${task} disabled successfully." -ForegroundColor Green
                $stats["TasksDisabled"]++
            } catch {
                Write-Warning "Failed to disable task ${task}: $_"
                $stats["TasksFailed"]++
            }
        }

        # Additional registry settings for telemetry
        $registryKeys = @(
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        )

        foreach ($key in $registryKeys) {
            try {
                if (-not (Test-Path $key)) {
                    Write-Host "Creating registry key: ${key}" -ForegroundColor Cyan
                    New-Item -Path $key -Force
                }
                Write-Host "Setting registry values for ${key}" -ForegroundColor Cyan
                Set-ItemProperty -Path $key -Name AllowTelemetry -Value 0 -Type DWord
                Set-ItemProperty -Path $key -Name DisableTelemetry -Value 1 -Type DWord
                Write-Host "Registry values for ${key} updated successfully." -ForegroundColor Green
                $stats["RegistryUpdated"]++
            } catch {
                Write-Warning "Failed to modify registry key ${key}: $_"
                $stats["RegistryFailed"]++
            }
        }

        Write-Host "Telemetry and tracking have been disabled." -ForegroundColor Green
    } catch {
        Write-Error "An error occurred while disabling telemetry: $_"
        exit 1
    }
}

# Check OS version and apply changes accordingly
If ($OSVersion -match "10\.0\.1[0-9]{4}") {
    Write-Host "Detected Windows 10 or 11. Proceeding with telemetry disabling steps." -ForegroundColor Green
    Disable-Telemetry
} elseif ($OSVersion -match "10\.0\.\d+") {
    Write-Host "Detected Windows Server. Proceeding with telemetry disabling steps." -ForegroundColor Green
    Disable-Telemetry
} else {
    Write-Error "This script is not designed for this OS version. Exiting."
    exit 1
}

# Stats Summary
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "CBKB - DeadlyData Script Execution Complete" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "Services Disabled: $($stats.ServicesDisabled)"
Write-Host "Services Failed: $($stats.ServicesFailed)"
Write-Host "Hosts Blocked: $($stats.HostsBlocked)"
Write-Host "Hosts Failed: $($stats.HostsFailed)"
Write-Host "Tasks Disabled: $($stats.TasksDisabled)"
Write-Host "Tasks Failed: $($stats.TasksFailed)"
Write-Host "Registry Keys Updated: $($stats.RegistryUpdated)"
Write-Host "Registry Keys Failed: $($stats.RegistryFailed)"

# Explicit success exit for PDQ Deploy
exit 0
