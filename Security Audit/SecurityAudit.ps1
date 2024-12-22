# Variables
$AuditLogPath = "C:\AuditLogs\SecurityAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$CSVLogPath   = "C:\AuditLogs\SecurityAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$CSVData      = @()

# Ensure Audit Log Directory Exists
if (-not (Test-Path "C:\AuditLogs")) {
    New-Item -ItemType Directory -Path "C:\AuditLogs" | Out-Null
}

# Function to Log Output (Text and CSV)
function Log {
    param (
        [string]$Message,
        [string]$Category = "General"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry  = "$Timestamp : $Category : $Message"
    $LogEntry  | Add-Content -Path $AuditLogPath
    Write-Output $LogEntry

    # Add to CSV Data
    $CSVData += [PSCustomObject]@{
        Timestamp = $Timestamp
        Category  = $Category
        Message   = $Message
    }
}

# Add Section Headers to Text Logs
function LogSection {
    param ([string]$Title)
    $Header = "=" * 60
    $SectionTitle = "`n$Header`n$Title`n$Header`n"  

    $SectionTitle | Add-Content -Path $AuditLogPath
    Write-Output $SectionTitle
}


# Check and Install Modules
function Ensure-Module {
    param (
        [string]$ModuleName,
        [string]$FeatureName = ""
    )
    try {
        if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
            Log "Module $ModuleName not found. Attempting installation..." "Modules"
            if ($FeatureName -ne "") {
                Install-WindowsFeature -Name $FeatureName -IncludeManagementTools -ErrorAction Stop
            } else {
                Install-Module -Name $ModuleName -Force -ErrorAction Stop
            }
            Log "Module $ModuleName installed successfully." "Modules"
        } else {
            Log "Module $ModuleName is available." "Modules"
        }
        Import-Module -Name $ModuleName -ErrorAction Stop
        Log "Module $ModuleName imported successfully." "Modules"
    } catch {
        Log "Failed to install or import module ${ModuleName}: ${($_.Exception.Message)} [ERROR]" "Modules"
    }
}

# Define a multiline banner string
$Banner = @"
########################################################################
#  CBKB - ElPadr1no
#  SECURITY AUDIT SCRIPT
#
#  This script runs a comprehensive security audit on a Windows system.
#  Logs are written to both text and CSV outputs for easy analysis.
########################################################################
"@

# Write the banner to the console and to the log file
$Banner | Out-File -FilePath $AuditLogPath -Append
Write-Output $Banner

# Optionally follow up with a LogSection for "SECURITY AUDIT START" or similar
LogSection "SECURITY AUDIT START"


# Ensure Required Modules
Ensure-Module -ModuleName "ActiveDirectory" -FeatureName "RSAT-AD-PowerShell"
Ensure-Module -ModuleName "PSWindowsUpdate"


###############################################################################
# SYSTEM INFORMATION
###############################################################################
LogSection "SYSTEM INFORMATION"
try {
    $OS      = Get-CimInstance Win32_OperatingSystem
    $Uptime  = (Get-Date) - $OS.LastBootUpTime

    Log "Operating System: $($OS.Caption), Version: $($OS.Version), Build: $($OS.BuildNumber), Manufacturer: $($OS.Manufacturer)" "System Info"
    Log "System Uptime: $($Uptime.Days) days $($Uptime.Hours) hours $($Uptime.Minutes) minutes" "System Info"
    Log "Original Install Date: $((Get-Date $OS.InstallDate).ToString('MM/dd/yyyy, HH:mm:ss'))" "System Info"

    $Memory = Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum
    Log "Total Physical Memory: $([math]::Round($Memory.Sum / 1GB, 2)) GB" "System Info"
    Log "Processor(s): $((Get-CimInstance Win32_Processor | ForEach-Object { ""$($_.Name) @ $($_.MaxClockSpeed) MHz"" }) -join ', ')" "System Info"
    Log "BIOS Version: $((Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion)" "System Info"
    Log "Windows Directory: $($OS.WindowsDirectory)" "System Info"
    Log "System Locale: $($OS.Locale)" "System Info"
    Log "Input Locale: $((Get-WinSystemLocale).Name)" "System Info"
    Log "Time Zone: $((Get-TimeZone).DisplayName)" "System Info"
} catch {
    Log "Error retrieving system information: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# DOMAIN GROUP POLICY AUDIT
###############################################################################
LogSection "DOMAIN GPO AUDIT"
try {
    # Use gpresult to get the current RSoP (Resultant Set of Policy)
    # /r - summary of policy
    # /scope computer - shows only computer-level settings
    #   (you can also /scope user if you want user-level GPOs)
    $gpResultOutput = gpresult /r /scope computer

    if ($gpResultOutput) {
        # Split the text output into lines for easy parsing
        $lines = $gpResultOutput -split "`r?`n"
        $insideAppliedGPOSection = $false

        foreach ($line in $lines) {
            # Trim whitespace for easier matching
            $trimmed = $line.Trim()

            # Detect the heading for Applied GPOs
            if ($trimmed -match "^Applied Group Policy Objects") {
                Log "[Computer-level] $trimmed" "Domain GPO"
                $insideAppliedGPOSection = $true
                continue
            }

            # If we are in the Applied GPO section, keep logging until a blank line
            if ($insideAppliedGPOSection) {
                if ([string]::IsNullOrWhiteSpace($trimmed)) {
                    $insideAppliedGPOSection = $false
                }
                else {
                    Log "  $trimmed" "Domain GPO"
                }
            }
        }
    }
    else {
        Log "No output from gpresult /r /scope computer. Possibly insufficient privileges or no domain GPOs applied." "Domain GPO"
    }
}
catch {
    Log "Error retrieving domain GPOs: $($_.Exception.Message) [ERROR]" "Domain GPO"
}


###############################################################################
# LOCAL SECURITY POLICY / SECURITY OPTIONS (Policy Names Only)
###############################################################################
LogSection "LOCAL SECURITY POLICY / SECURITY OPTIONS"
try {
    # Category definitions (like before)
    $SecurityOptions = @{
        "UAC Policies" = @{
            "EnableLUA"                  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableLUA"
            "ConsentPromptBehaviorAdmin" = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:ConsentPromptBehaviorAdmin"
            "FilterAdministratorToken"   = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:FilterAdministratorToken"
        }
        "LSA Policies" = @{
            "LimitBlankPasswordUse"      = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa:LimitBlankPasswordUse"
            "RestrictAnonymous"          = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa:RestrictAnonymous"
            "DisableDomainCreds"         = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa:DisableDomainCreds"
            "NoLMHash"                   = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa:NoLMHash"
        }
        "Other Security Options" = @{
            "CachedLogonsCount"          = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:CachedLogonsCount"
        }
    }

    foreach ($category in $SecurityOptions.Keys) {
        # Print category heading
        Log "** $category **" "Local Security Policy"

        foreach ($policy in $SecurityOptions[$category].GetEnumerator()) {
            $policyName = $policy.Key
            $fullString = $policy.Value

            # Separate registry path and value name
            $lastColonIndex = $fullString.LastIndexOf(":")
            if ($lastColonIndex -ge 0) {
                $regPath      = $fullString.Substring(0, $lastColonIndex)
                $regValueName = $fullString.Substring($lastColonIndex + 1)
            }
            else {
                continue
            }

            # Check if registry path exists and value is set
            if (Test-Path $regPath) {
                $regItem  = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue
                $regValue = $regItem.$regValueName
                if ($null -ne $regValue) {
                    # Just log the policy name if it has a non-null setting
                    Log "$policyName" "Local Security Policy"
                }
            }
        }
    }
}
catch {
    Log "Error auditing local security options: $($_.Exception.Message) [ERROR]" "Local Security Policy"
}







###############################################################################
# SECURITY UPDATE COMPLIANCE
###############################################################################
LogSection "SECURITY UPDATE COMPLIANCE"
try {
    $Updates = Get-HotFix | Where-Object { $_.Description -eq "Security Update" }
    if ($Updates) {
        foreach ($update in $Updates) {
            Log "Security Update Installed: $($update.HotFixID), Installed On: $($update.InstalledOn)" "Updates"
        }
    } else {
        Log "No security updates found. [WARNING]" "Updates"
    }

    if (Get-Command -Name Get-WindowsUpdate -ErrorAction SilentlyContinue) {
        $MissingUpdates = Get-WindowsUpdate -Criteria "IsInstalled=0 AND Type='Software'"
        if ($MissingUpdates) {
            foreach ($update in $MissingUpdates) {
                Log "Missing Security Update: $($update.KBArticle), Title: $($update.Title)" "Updates"
            }
        } else {
            Log "No missing security updates detected." "Updates"
        }
    } else {
        Log "PSWindowsUpdate module not available. Skipping missing update check." "Updates"
    }
} catch {
    Log "Error retrieving update status: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# SOFTWARE INVENTORY
###############################################################################
LogSection "SOFTWARE INVENTORY"
try {
    # Registry paths to check:
    #  - 64-bit: HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall
    #  - 32-bit on 64-bit OS: HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
    $UninstallPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($regPath in $UninstallPaths) {
        if (Test-Path $regPath) {
            Log "Checking registry path: $regPath" "Software Inventory"

            # Enumerate each subkey under the Uninstall path
            $subKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
            foreach ($subKey in $subKeys) {
                try {
                    $item       = Get-ItemProperty -Path $subKey.PSPath -ErrorAction SilentlyContinue
                    $appName    = $item.DisplayName
                    $appVersion = $item.DisplayVersion
                    $publisher  = $item.Publisher

                    # Only log it if there's at least a DisplayName
                    if ($appName) {
                        Log ("App: {0}, Version: {1}, Publisher: {2}" -f $appName, $appVersion, $publisher) "Software Inventory"
                    }
                } catch {
                    # Some subkeys don't have readable properties, or we lack permissions
                    Log "Error reading subkey '$($subKey.Name)': $($_.Exception.Message) [WARNING]" "Software Inventory"
                }
            }
        }
        else {
            Log "Registry path not found: $regPath" "Software Inventory"
        }
    }
}
catch {
    Log "Error enumerating installed software: $($_.Exception.Message) [ERROR]" "Software Inventory"
}

###############################################################################
# FIREWALL STATUS
###############################################################################
LogSection "FIREWALL STATUS"
try {
    $FirewallProfiles = Get-NetFirewallProfile
    foreach ($profile in $FirewallProfiles) {
        $Status = if ($profile.Enabled -eq $true) { "Enabled" } else { "Disabled" }
        Log "Firewall Profile: $($profile.Name), Status: $Status" "Firewall"
        Log "Inbound Connections: $($profile.DefaultInboundAction), Outbound Connections: $($profile.DefaultOutboundAction)" "Firewall"
    }
} catch {
    Log "Error retrieving firewall status: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# OPEN PORTS AND LISTENING SERVICES
###############################################################################
LogSection "OPEN PORTS AND LISTENING SERVICES"
try {
    $Ports = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" }
    foreach ($port in $Ports) {
        $ProcessName = (Get-Process -Id $port.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        Log "Port $($port.LocalPort): Listening (Process: $ProcessName)" "Network"
    }
} catch {
    Log "Error retrieving open ports: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# STARTUP ITEM CHECK (Already Present; Renaming to "AUDIT STARTUP PROGRAMS")
###############################################################################
LogSection "AUDIT STARTUP PROGRAMS"
try {
    $StartupItems = Get-CimInstance -ClassName Win32_StartupCommand
    if ($StartupItems) {
        foreach ($item in $StartupItems) {
            $Status = if ($item.User -ne $null) { "Enabled" } else { "Disabled" }
            Log "Startup Item: $($item.Name), Command: $($item.Command), Location: $($item.Location), Status: $Status" "Startup Items"
        }
    } else {
        Log "No startup items found." "Startup Items"
    }
} catch {
    Log "Error retrieving startup items: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# GROUP MEMBERSHIP VALIDATION
###############################################################################
LogSection "Domain GROUP MEMBERSHIP VALIDATION"
$SensitiveGroups = @("Domain Admins", "Administrators", "Enterprise Admins")
foreach ($group in $SensitiveGroups) {
    try {
        $GroupMembers = Get-ADGroupMember -Identity $group -Recursive
        Log "Group: $group, Members:" "Group Membership"
        foreach ($member in $GroupMembers) {
            Log "    $($member.Name)" "Group Membership"
        }
    } catch {
        Log "Error retrieving members for group ${group}: ${($_.Exception.Message)} [ERROR]" "Error"
    }
}

###############################################################################
# ACCOUNT AND IDENTITY MANAGEMENT
###############################################################################
LogSection "ACCOUNT AND IDENTITY MANAGEMENT"

try {
    # Retrieve Local Accounts
    Log "**Local Accounts**" "Account Management"
    Log "------------------------------------------------------------" "Account Management"
    $LocalAccounts = Get-LocalUser
    foreach ($account in $LocalAccounts) {
        $PasswordExpiration = if ($account.PasswordExpires) {
            $account.PasswordLastSet.AddDays($account.PasswordSettings.MaxPasswordAge.Days).ToString("MM/dd/yyyy")
        } else { 
            "No Expiration"
        }
        Log "- **$($account.Name)**" "Account Management"
        Log "  - Enabled: $($account.Enabled)" "Account Management"
        Log "  - Password Expiry: $PasswordExpiration" "Account Management"
    }

    # Retrieve Local Groups and Members
    Log "" "Account Management"
    Log "**Local Groups and Members**" "Account Management"
    Log "------------------------------------------------------------" "Account Management"
    $LocalGroups = Get-LocalGroup
    foreach ($group in $LocalGroups) {
        Log "- **$($group.Name)**" "Account Management"
        $GroupMembers = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
        if ($GroupMembers) {
            foreach ($member in $GroupMembers) {
                Log "  - $($member.Name) ($($member.ObjectClass))" "Account Management"
            }
        } else {
            Log "  - No members" "Account Management"
        }
    }

    # Retrieve Local Administrators
    Log "" "Account Management"
    Log "**Local Administrators**" "Account Management"
    Log "------------------------------------------------------------" "Account Management"
    $LocalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    if ($LocalAdmins) {
        foreach ($admin in $LocalAdmins) {
            Log "- $($admin.Name) ($($admin.ObjectClass))" "Account Management"
        }
    } else {
        Log "No members found in the Administrators group." "Account Management"
    }

    # Retrieve Remote Desktop Users
    Log "" "Account Management"
    Log "**Remote Desktop Users**" "Account Management"
    Log "------------------------------------------------------------" "Account Management"
    $RemoteDesktopUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
    if ($RemoteDesktopUsers) {
        foreach ($user in $RemoteDesktopUsers) {
            Log "- $($user.Name) ($($user.ObjectClass))" "Account Management"
        }
    } else {
        Log "No members found in the Remote Desktop Users group." "Account Management"
    }

    # Retrieve Local Account Lockout Policy
    Log "" "Account Management"
    Log "**Local Account Lockout Policy**" "Account Management"
    Log "------------------------------------------------------------" "Account Management"
    $LockoutThreshold    = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ErrorAction SilentlyContinue).LockoutThreshold
    $ObservationWindow   = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ErrorAction SilentlyContinue).LockoutObservationWindow

    if ($null -ne $LockoutThreshold) {
        Log "- Lockout Threshold: $LockoutThreshold" "Account Management"
    } else {
        Log "- Lockout Threshold: Not Configured" "Account Management"
    }

    if ($null -ne $ObservationWindow) {
        Log "- Observation Window: $ObservationWindow seconds" "Account Management"
    } else {
        Log "- Observation Window: Not Configured" "Account Management"
    }

} catch {
    Log "Error retrieving account and identity management information: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# ANTIVIRUS STATUS (Enhanced)
###############################################################################
LogSection "ANTIVIRUS STATUS"
try {
    $AntivirusStatus = Get-MpComputerStatus

    Log "Antivirus Enabled: $($AntivirusStatus.AntivirusEnabled)" "Antivirus"
    Log "Real-Time Protection Enabled: $($AntivirusStatus.RealTimeProtectionEnabled)" "Antivirus"
    Log "Last Scan Time: $($AntivirusStatus.LastQuickScanTime)" "Antivirus"

    # Additional signature info
    Log "Antivirus Signature Version: $($AntivirusStatus.AntivirusSignatureVersion)" "Antivirus"
    Log "Antivirus Signature Last Updated: $($AntivirusStatus.NISSignatureLastUpdated)" "Antivirus"

} catch {
    Log "Error retrieving antivirus status: ${($_.Exception.Message)} [ERROR]" "Error"
}


###############################################################################
# DISK SPACE UTILIZATION
###############################################################################
LogSection "DISK SPACE UTILIZATION"
try {
    $Disks = Get-PSDrive -PSProvider FileSystem
    foreach ($disk in $Disks) {
        $FreeSpaceGB = [math]::Round($disk.Free / 1GB, 2)
        $UsedSpaceGB = [math]::Round($disk.Used / 1GB, 2)
        Log "Drive: $($disk.Name), Free Space: $FreeSpaceGB GB, Used Space: $UsedSpaceGB GB" "Disk Utilization"
        if ($FreeSpaceGB -lt 10) {
            Log "WARNING: Drive $($disk.Name) is running low on space. Only $FreeSpaceGB GB left!" "Disk Utilization"
        }
    }
} catch {
    Log "Error retrieving disk space information: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# SHARED FOLDERS AND PERMISSIONS
###############################################################################
LogSection "SHARED FOLDERS AND PERMISSIONS"
try {
    # Retrieve all shared folders excluding admin shares
    $SharedFolders = Get-SmbShare | Where-Object { $_.Name -notin "C$", "ADMIN$", "IPC$" }
    if ($SharedFolders) {
        foreach ($share in $SharedFolders) {
            Log "**$($share.Name)**" "Shared Folders"
            Log "------------------------------------------------------------" "Shared Folders"
            Log "- Path: $($share.Path)" "Shared Folders"

            # Combine Share Permissions and NTFS Permissions
            $PermissionsOutput = @{}

            # Get Share Permissions
            $SharePermissions = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
            if ($SharePermissions) {
                foreach ($permission in $SharePermissions) {
                    $PermissionsOutput[$permission.Name] = $permission.AccessRight
                }
            }

            # Get NTFS Permissions
            if (Test-Path -Path $share.Path) {
                $NTFSPermissions = Get-Acl -Path $share.Path | Select-Object -ExpandProperty Access
                foreach ($ntfs in $NTFSPermissions) {
                    $User   = $ntfs.IdentityReference.ToString()
                    $Rights = $ntfs.FileSystemRights.ToString()
                    if ($PermissionsOutput.ContainsKey($User)) {
                        $PermissionsOutput[$User] += ", NTFS: $Rights"
                    } else {
                        $PermissionsOutput[$User] = "NTFS: $Rights"
                    }
                }
            }

            # Log Consolidated Permissions
            if ($PermissionsOutput.Count -gt 0) {
                foreach ($key in $PermissionsOutput.Keys) {
                    Log "- ${key}: $($PermissionsOutput[$key])" "Shared Folders"
                }
            } else {
                Log "- No permissions found." "Shared Folders"
            }
        }
    } else {
        Log "No shared folders found." "Shared Folders"
    }
} catch {
    Log "Error retrieving shared folders or permissions: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# SUSPICIOUS AND CUSTOM SCHEDULED TASKS
###############################################################################
LogSection "SUSPICIOUS AND CUSTOM SCHEDULED TASKS"
try {
    # Retrieve all scheduled tasks outside the \Microsoft\ path
    $Tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' }
    if ($Tasks) {
        foreach ($task in $Tasks) {
            $TaskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
            Log "Task: $($task.TaskName), Path: $($task.TaskPath), State: $($task.State)" "Scheduled Tasks"
            Log "    Next Run Time: $($TaskInfo.NextRunTime)" "Scheduled Tasks"
            Log "    Last Run Time: $($TaskInfo.LastRunTime)" "Scheduled Tasks"
            Log "    Last Task Result: $($TaskInfo.LastTaskResult)" "Scheduled Tasks"

            # Check for suspicious tasks based on common malicious strings
            $Actions = $task.Actions | ForEach-Object { $_.Execute -join ";" }
            if ($Actions -match "(powershell|cmd|wscript|cscript|ftp|curl|wget|encodedcommand)") {
                Log "    WARNING: Suspicious action detected in task $($task.TaskName): $Actions" "Scheduled Tasks"
            }
        }
    } else {
        Log "No custom or suspicious scheduled tasks found." "Scheduled Tasks"
    }
} catch {
    Log "Error retrieving scheduled tasks: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# CHECK POWERSHELL EXECUTION POLICY
###############################################################################
LogSection "POWERSHELL EXECUTION POLICY"
try {
    $PSExecutionPolicy = Get-ExecutionPolicy -List
    foreach ($policy in $PSExecutionPolicy) {
        Log "Scope: $($policy.Scope), Execution Policy: $($policy.ExecutionPolicy)" "Execution Policy"
    }
} catch {
    Log "Error retrieving PowerShell Execution Policy: ${($_.Exception.Message)} [ERROR]" "Error"
}

 

###############################################################################
# SUSPICIOUS PROCESS SCAN (Refined pslist Parsing)
###############################################################################
LogSection "SUSPICIOUS PROCESS SCAN"
try {
    # Define criteria
    $SuspiciousProcesses = @("powershell", "cmd", "wscript", "cscript", "mshta", "winword", "excel")
    $CpuThreshold         = 50  # e.g. 50% average CPU usage over lifetime
    $MemoryThresholdMB    = 500 # e.g. 500 MB of private memory

    # Ensure local path exists
    if (-not (Test-Path "C:\tmp\Files")) {
        New-Item -ItemType Directory -Path "C:\tmp\Files" | Out-Null
    }

    # Download pslist.exe if not already present
    $UrlPsList         = "https://live.sysinternals.com/pslist.exe"
    $PsListDestination = "C:\tmp\Files\pslist.exe"

    if (-not (Test-Path $PsListDestination)) {
        Invoke-WebRequest -Uri $UrlPsList -OutFile $PsListDestination -UseBasicParsing
        Log "Downloaded pslist.exe from $UrlPsList" "Processes"
    } else {
        Log "pslist.exe found at $PsListDestination. Skipping download." "Processes"
    }

    # Function to parse HH:MM:SS.mmm to total seconds
    function Convert-ToSeconds {
        param([string]$timeStr)

        # Example timeStr: "0:05:21.500" => HH:MM:SS.mmm
        # Split on ':' => [Hours, Minutes, Seconds.millis]
        $parts     = $timeStr -split ':'
        $hours     = [int]$parts[0]
        $minutes   = [int]$parts[1]
        $secMillis = $parts[2] -split '\.'
        $seconds   = [int]$secMillis[0]
        $millis    = 0
        if ($secMillis.Count -gt 1) {
            $millis = [int]$secMillis[1]
        }
        return ($hours * 3600) + ($minutes * 60) + $seconds + ($millis / 1000)
    }

    # Run pslist if it exists
    if (Test-Path $PsListDestination) {
        # Execute pslist and skip the first few header lines
        # Default columns:
        #   Name, Pid, Pri, Thd, Hnd, Priv, CPU Time, Elapsed Time
        $PsListOutput = & $PsListDestination -accepteula | Select-String -NotMatch "Name|^---|PsList"

        foreach ($line in $PsListOutput) {
            $fields = $line -split "\s{2,}"

            # Ensure we have enough columns
            if ($fields.Count -ge 8) {
                $processName   = $fields[0]
                $processId     = $fields[1]
                $priority      = $fields[2]
                $threads       = $fields[3]
                $handles       = $fields[4]
                $privKB        = $fields[5] -replace '[^\d]', ''  # remove non-numeric
                $cpuTimeRaw    = $fields[6]                      # e.g. "0:05:21.500"
                $elapsedTime   = $fields[7]                      # e.g. "0:10:00.000"

                # Convert "Priv" from KB to MB
                $privMB = 0
                if ($privKB) {
                    $privMB = [math]::Round(($privKB -as [double]) / 1024, 2)
                }

                # Convert times to seconds
                $cpuSeconds     = Convert-ToSeconds $cpuTimeRaw
                $elapsedSeconds = Convert-ToSeconds $elapsedTime

                # Calculate approximate lifetime CPU usage
                $cpuUsagePercent = 0
                if ($elapsedSeconds -gt 0) {
                    $cpuUsagePercent = [math]::Round(($cpuSeconds / $elapsedSeconds) * 100, 2)
                }

                # Check suspicious by name
                if ($processName -in $SuspiciousProcesses) {
                    Log "Suspicious process detected by name: $processName (PID: $processId)" "Processes"
                }

                # Check CPU usage threshold
                if ($cpuUsagePercent -gt $CpuThreshold) {
                    Log "High CPU usage detected: $processName (PID: $processId), CPU: $cpuUsagePercent%" "Processes"
                }

                # Check memory usage threshold
                if ($privMB -gt $MemoryThresholdMB) {
                    Log "High memory usage detected: $processName (PID: $processId), Memory: $privMB MB" "Processes"
                }
            }
        }
    } else {
        Log "pslist.exe not found after attempted download. Skipping Sysinternals-based process scan." "Processes"
    }
} catch {
    Log "Error scanning for suspicious processes with pslist: $($_.Exception.Message) [ERROR]" "Error"
}



###############################################################################
# CHECK REGISTRY FOR PERSISTENCE (Using Sysinternals autorunsc.exe)
###############################################################################
LogSection "REGISTRY PERSISTENCE CHECK"
try {
    # Ensure local path exists
    if (-not (Test-Path "C:\tmp\Files")) {
        New-Item -ItemType Directory -Path "C:\tmp\Files" | Out-Null
    }

    # Download autorunsc.exe if not already present
    $UrlAutoruns         = "https://live.sysinternals.com/autorunsc.exe"
    $AutorunsDestination = "C:\tmp\Files\autorunsc.exe"

    if (-not (Test-Path $AutorunsDestination)) {
        Invoke-WebRequest -Uri $UrlAutoruns -OutFile $AutorunsDestination -UseBasicParsing
        Log "Downloaded autorunsc.exe from $UrlAutoruns" "Registry Persistence"
    } else {
        Log "autorunsc.exe found at $AutorunsDestination. Skipping download." "Registry Persistence"
    }

    # Run autorunsc if it exists
    if (Test-Path $AutorunsDestination) {
        # -m includes most startup items; -accepteula / -nobanner remove prompts
        $AutorunsOutput = & $AutorunsDestination -accepteula -nobanner -m 2>&1

        foreach ($line in $AutorunsOutput) {
            Log "Autoruns: $line" "Registry Persistence"
        }
    } else {
        Log "autorunsc.exe not found after attempted download. Skipping Sysinternals-based registry check." "Registry Persistence"
    }
} catch {
    Log "Error checking registry for persistence with autorunsc: $($_.Exception.Message) [ERROR]" "Error"
}


###############################################################################
# CHECK RDP STATUS AND ENABLE IF OFF
###############################################################################
LogSection "RDP STATUS"
try {
    $RDPRegistryPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
    $RDPValue        = Get-ItemProperty -Path $RDPRegistryPath -Name fDenyTSConnections -ErrorAction SilentlyContinue

    if ($RDPValue.fDenyTSConnections -eq 1) {
        Log "RDP is currently disabled. Enabling now..." "RDP"
        Set-ItemProperty -Path $RDPRegistryPath -Name fDenyTSConnections -Value 0 -ErrorAction SilentlyContinue
        
        # Enable the Remote Desktop firewall rule group if needed
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        
        Log "RDP has been enabled successfully." "RDP"
    } else {
        Log "RDP is already enabled." "RDP"
    }
} catch {
    Log "Error checking or modifying RDP status: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# SSL/TLS CONFIGURATION
###############################################################################
LogSection "SSL/TLS CONFIGURATION"
try {
    # Check if the "Get-TlsCipherSuite" cmdlet is available (Windows Server 2019+ / PS 5.1+).
    if (Get-Command -Name Get-TlsCipherSuite -ErrorAction SilentlyContinue) {
        $CipherSuites = Get-TlsCipherSuite
        if ($CipherSuites) {
            Log "Supported Cipher Suites:" "SSL/TLS"
            foreach ($suite in $CipherSuites) {
                Log "  - Name: $($suite.Name), Protocol: $($suite.Protocol), Exchange: $($suite.KeyExchangeAlgorithm)" "SSL/TLS"
            }
        } else {
            Log "No cipher suites found or Get-TlsCipherSuite returned empty." "SSL/TLS"
        }
    } else {
        Log "Get-TlsCipherSuite not available. This may be an older OS version or PowerShell version." "SSL/TLS"
        Log "Manual check or registry check under SCHANNEL may be required." "SSL/TLS"
    }

    # You can also check SCHANNEL registry keys for SSL/TLS versions:
    $SChannelPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    if (Test-Path $SChannelPath) {
        Log "Checking SCHANNEL Protocols in registry:" "SSL/TLS"
        $Protocols = Get-ChildItem -Path $SChannelPath -ErrorAction SilentlyContinue
        foreach ($proto in $Protocols) {
            Log "Protocol: $($proto.PSChildName)" "SSL/TLS"
            $ClientKeyPath = Join-Path $proto.PSPath "Client"
            $ServerKeyPath = Join-Path $proto.PSPath "Server"
            foreach ($subPath in @($ClientKeyPath, $ServerKeyPath)) {
                if (Test-Path $subPath) {
                    $DisabledByDefault = (Get-ItemProperty -Path $subPath -Name "DisabledByDefault" -ErrorAction SilentlyContinue).DisabledByDefault
                    $Enabled           = (Get-ItemProperty -Path $subPath -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
                    Log "  SubKey: $subPath, DisabledByDefault: $DisabledByDefault, Enabled: $Enabled" "SSL/TLS"
                }
            }
        }
    } else {
        Log "SCHANNEL registry path not found. Cannot check SSL/TLS version settings." "SSL/TLS"
    }
}
catch {
    Log "Error auditing SSL/TLS configuration: $($_.Exception.Message) [ERROR]" "SSL/TLS"
}


###############################################################################
# AUDIT SMB SETTINGS
###############################################################################
LogSection "AUDIT SMB SETTINGS"
try {
    $SmbServerConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($SmbServerConfig) {
        Log "SMB Server Configuration:" "SMB"
        Log "  - SMB1 Enabled: $($SmbServerConfig.EnableSMB1Protocol)" "SMB"
        Log "  - SMB2 Enabled: $($SmbServerConfig.EnableSMB2Protocol)" "SMB"
        Log "  - EncryptData: $($SmbServerConfig.EncryptData)" "SMB"
        Log "  - RequireSecuritySignature: $($SmbServerConfig.RequireSecuritySignature)" "SMB"
        Log "  - RejectUnencryptedAccess: $($SmbServerConfig.RequireSecureNegotiate)" "SMB"
    } else {
        Log "Unable to retrieve SMB Server Configuration. (Requires Windows Server 2012+)" "SMB"
    }

    $SmbClientConfig = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
    if ($SmbClientConfig) {
        Log "SMB Client Configuration:" "SMB"
        Log "  - EnableSMB1Protocol: $($SmbClientConfig.EnableSMB1Protocol)" "SMB"
        Log "  - EnableSMB2Protocol: $($SmbClientConfig.EnableSMB2Protocol)" "SMB"
        Log "  - RequireSecuritySignature: $($SmbClientConfig.RequireSecuritySignature)" "SMB"
    } else {
        Log "Unable to retrieve SMB Client Configuration." "SMB"
    }
} catch {
    Log "Error auditing SMB settings: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# INSTALLED SERVER CERTIFICATES (Unfiltered)
###############################################################################
LogSection "INSTALLED SERVER CERTIFICATES"
try {
    # Check the LocalMachine\My (Personal) store for all certificates
    $CertPath = "Cert:\LocalMachine\My"
    if (Test-Path $CertPath) {
        $AllCerts = Get-ChildItem -Path $CertPath -ErrorAction SilentlyContinue
        
        if ($AllCerts) {
            foreach ($cert in $AllCerts) {
                Log "Thumbprint: $($cert.Thumbprint), Subject: $($cert.Subject), Expires: $($cert.NotAfter)" "Certificates"
                Log "  Issuer: $($cert.Issuer), FriendlyName: $($cert.FriendlyName), HasPrivateKey: $($cert.HasPrivateKey)" "Certificates"
            }
        }
        else {
            Log "No certificates found in LocalMachine\My." "Certificates"
        }
    }
    else {
        Log "Certificate store path not found: $CertPath" "Certificates"
    }
}
catch {
    Log "Error enumerating installed certificates: $($_.Exception.Message) [ERROR]" "Certificates"
}



###############################################################################
# LIST SHADOW COPIES
###############################################################################
LogSection "LIST SHADOW COPIES"
try {
    # VSSAdmin list shadows
    $ShadowCopies = vssadmin list shadows
    if ($ShadowCopies) {
        $ShadowCopies -split "`r?`n" | ForEach-Object { Log $_ "Shadow Copies" }
    } else {
        Log "No shadow copies found or unable to retrieve." "Shadow Copies"
    }
} catch {
    Log "Error listing shadow copies: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# CHECK BITLOCKER STATUS
###############################################################################
LogSection "CHECK BITLOCKER STATUS"
try {
    if (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        $BitlockerVolumes = Get-BitLockerVolume
        foreach ($volume in $BitlockerVolumes) {
            Log "Drive: $($volume.VolumeLetter), Protection Status: $($volume.ProtectionStatus), Lock Status: $($volume.LockStatus)" "BitLocker"
        }
    } else {
        Log "BitLocker module not available. Skipping BitLocker status check." "BitLocker"
    }
} catch {
    Log "Error retrieving BitLocker status: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# CHECK LOGON EVENTS
###############################################################################
LogSection "CHECK LOGON EVENTS"
try {
    # Latest 20 logon events (Event ID 4624 for successful logons)
    $LogonEvents = Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624)]]" -MaxEvents 20
    if ($LogonEvents) {
        foreach ($event in $LogonEvents) {
            $TimeCreated = $event.TimeCreated
            $UserData    = $event.Properties[5].Value
            Log "Logon Event at $TimeCreated by User: $UserData" "Logon Events"
        }
    } else {
        Log "No recent logon events found." "Logon Events"
    }
} catch {
    Log "Error retrieving logon events: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# CHECK RECENT SECURITY EVENTS
###############################################################################
LogSection "CHECK RECENT SECURITY EVENTS"
try {
    # Retrieve latest 20 Security log events (generic)
    $SecurityEvents = Get-WinEvent -LogName Security -MaxEvents 20
    if ($SecurityEvents) {
        foreach ($event in $SecurityEvents) {
            Log "Event ID: $($event.Id), Time: $($event.TimeCreated), User: $($event.Properties[1].Value)" "Security Events"
        }
    } else {
        Log "No recent security events found." "Security Events"
    }
} catch {
    Log "Error retrieving recent security events: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# LIST ARP TABLE
###############################################################################
LogSection "LIST ARP TABLE"
try {
    $ArpEntries = arp -a
    if ($ArpEntries) {
        $ArpEntries -split "`r?`n" | ForEach-Object {
            Log $_ "ARP"
        }
    } else {
        Log "No ARP entries found." "ARP"
    }
} catch {
    Log "Error retrieving ARP table: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# LIST NETWORK ADAPTERS AND IPs
###############################################################################
LogSection "LIST NETWORK ADAPTERS AND IPS"
try {
    $Adapters = Get-NetIPConfiguration
    if ($Adapters) {
        foreach ($adapter in $Adapters) {
            $ifDesc  = $adapter.InterfaceDescription
            $ifAlias = $adapter.InterfaceAlias
            $ipAddr  = $adapter.IPv4Address.IPAddress
            Log "Adapter: $ifAlias / $ifDesc, IPv4 Address: $ipAddr" "Network Adapters"
        }
    } else {
        Log "No network adapters found." "Network Adapters"
    }
} catch {
    Log "Error listing network adapters: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# VALIDATE ACTIVE CONNECTIONS
###############################################################################
LogSection "VALIDATE ACTIVE CONNECTIONS"
try {
    # Show both TCP and UDP connections using netstat for completeness
    $Netstat = netstat -ano
    foreach ($line in $Netstat) {
        Log $line "Netstat"
    }
} catch {
    Log "Error validating active connections: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# AUDIT DNS SETTINGS
###############################################################################
LogSection "AUDIT DNS SETTINGS"
try {
    $DNSConfigs = Get-DnsClientServerAddress -ErrorAction SilentlyContinue
    if ($DNSConfigs) {
        foreach ($dnsConfig in $DNSConfigs) {
            $InterfaceAlias = $dnsConfig.InterfaceAlias
            $ServerIPs      = $dnsConfig.ServerAddresses -join ", "
            Log "Interface: $InterfaceAlias, DNS Servers: $ServerIPs" "DNS"
        }
    } else {
        Log "No DNS client configurations found." "DNS"
    }
} catch {
    Log "Error auditing DNS settings: ${($_.Exception.Message)} [ERROR]" "Error"
}


###############################################################################
# BROWSER SECURITY SETTINGS
###############################################################################
LogSection "BROWSER SECURITY SETTINGS"
try {
    # Ensure local path for BrowserHistory exists
    $BrowserHistoryPath = "C:\tmp\Files\BrowserHistory"
    if (-not (Test-Path $BrowserHistoryPath)) {
        New-Item -ItemType Directory -Path $BrowserHistoryPath | Out-Null
    }

    ############################################################################
    # 1) INTERNET EXPLORER SECURITY SETTINGS
    ############################################################################
    Log "=== Internet Explorer Settings ===" "Browser"
    # Check a few common registry locations for IE settings:
    #   HKCU:\Software\Microsoft\Internet Explorer
    #   HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    #   Security Zones at HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones
    try {
        $IEKeyPaths = @(
            "HKCU:\Software\Microsoft\Internet Explorer",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        )
        foreach ($regPath in $IEKeyPaths) {
            if (Test-Path $regPath) {
                $values = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                foreach ($prop in $values.PSObject.Properties) {
                    if ($prop.Name -notmatch "^PS") {
                        Log "IE Registry $regPath -> $($prop.Name) = $($prop.Value)" "Browser"
                    }
                }
            }
        }

        # Enumerate IE security zones
        $ZonesPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones"
        if (Test-Path $ZonesPath) {
            $ZoneFolders = Get-ChildItem $ZonesPath -ErrorAction SilentlyContinue
            foreach ($zone in $ZoneFolders) {
                $ZoneValues = Get-ItemProperty -Path $zone.PSPath
                foreach ($prop in $ZoneValues.PSObject.Properties) {
                    if ($prop.Name -notmatch "^PS") {
                        Log "IE Zone $($zone.PSChildName) -> $($prop.Name) = $($prop.Value)" "Browser"
                    }
                }
            }
        }
    } catch {
        Log "Error retrieving Internet Explorer settings: $($_.Exception.Message) [ERROR]" "Browser"
    }

    ############################################################################
    # 2) EDGE (Chromium-based) SECURITY/POLICY SETTINGS
    ############################################################################
    Log "" "Browser"
    Log "=== Microsoft Edge (Chromium) Settings ===" "Browser"
    try {
        # Standard policy locations:
        #  - HKCU:\Software\Policies\Microsoft\Edge
        #  - HKLM:\Software\Policies\Microsoft\Edge
        $EdgePolicyKeys = @(
            "HKCU:\Software\Policies\Microsoft\Edge",
            "HKLM:\Software\Policies\Microsoft\Edge"
        )
        foreach ($edgeKey in $EdgePolicyKeys) {
            if (Test-Path $edgeKey) {
                $EdgeValues = Get-ItemProperty -Path $edgeKey -ErrorAction SilentlyContinue
                foreach ($prop in $EdgeValues.PSObject.Properties) {
                    if ($prop.Name -notmatch "^PS") {
                        Log "Edge Policy $edgeKey -> $($prop.Name) = $($prop.Value)" "Browser"
                    }
                }
            }
        }
    } catch {
        Log "Error retrieving Microsoft Edge settings: $($_.Exception.Message) [ERROR]" "Browser"
    }

    ############################################################################
    # 3) GOOGLE CHROME SECURITY/POLICY SETTINGS
    ############################################################################
    Log "" "Browser"
    Log "=== Google Chrome Settings ===" "Browser"
    try {
        # Chrome GPO policy locations:
        #  - HKCU:\Software\Policies\Google\Chrome
        #  - HKLM:\Software\Policies\Google\Chrome
        $ChromePolicyKeys = @(
            "HKCU:\Software\Policies\Google\Chrome",
            "HKLM:\Software\Policies\Google\Chrome"
        )
        foreach ($chromeKey in $ChromePolicyKeys) {
            if (Test-Path $chromeKey) {
                $ChromeValues = Get-ItemProperty -Path $chromeKey -ErrorAction SilentlyContinue
                foreach ($prop in $ChromeValues.PSObject.Properties) {
                    if ($prop.Name -notmatch "^PS") {
                        Log "Chrome Policy $chromeKey -> $($prop.Name) = $($prop.Value)" "Browser"
                    }
                }
            }
        }

        # You could also parse JSON config files in each user’s Chrome profile (Preferences),
        # typically found in:
        #   C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\Preferences
        # For brevity, we omit deep JSON parsing here, but you can add it if needed.
    } catch {
        Log "Error retrieving Chrome settings: $($_.Exception.Message) [ERROR]" "Browser"
    }

    ############################################################################
    # 4) MOZILLA FIREFOX SECURITY SETTINGS
    ############################################################################
    Log "" "Browser"
    Log "=== Mozilla Firefox Settings ===" "Browser"
    try {
        # Common policy location in Windows Registry:
        #  - HKCU:\Software\Policies\Mozilla\Firefox
        $FirefoxRegKey = "HKCU:\Software\Policies\Mozilla\Firefox"
        if (Test-Path $FirefoxRegKey) {
            $FFValues = Get-ItemProperty -Path $FirefoxRegKey -ErrorAction SilentlyContinue
            foreach ($prop in $FFValues.PSObject.Properties) {
                if ($prop.Name -notmatch "^PS") {
                    Log "Firefox Policy -> $($prop.Name) = $($prop.Value)" "Browser"
                }
            }
        }

        # Additional advanced config in "about:config" is stored in profile prefs.js:
        #   C:\Users\<USER>\AppData\Roaming\Mozilla\Firefox\Profiles\<Profile>\prefs.js
        # You can parse that file line by line, searching for "user_pref("X", "Y");"
        # For example:
        #   user_pref("browser.safebrowsing.enabled", true);
    } catch {
        Log "Error retrieving Firefox settings: $($_.Exception.Message) [ERROR]" "Browser"
    }

    ############################################################################
    # WHITELIST / BLACKLIST
    ############################################################################
    Log "" "Browser"
    Log "=== Browser Whitelists / Blacklists ===" "Browser"
    try {
        # Many enterprise environments store whitelists/blacklists in browser policies:
        #   Chrome -> 'URLBlacklist', 'URLWhitelist' in HKCU:\Software\Policies\Google\Chrome
        #   Edge (Chromium) -> 'URLBlacklist', 'URLAllowlist' in HKCU:\Software\Policies\Microsoft\Edge
        #   Firefox -> In about:config or user.js/prefs.js (may store as "extensions.blocklist.enabled")

        # This snippet just logs if we find typical policy-based keys for Chrome or Edge
        $ChromeBLKey = "HKCU:\Software\Policies\Google\Chrome"
        if (Test-Path $ChromeBLKey) {
            $ChromePolicy = Get-ItemProperty -Path $ChromeBLKey -ErrorAction SilentlyContinue
            if ($ChromePolicy.URLBlacklist) {
                Log "Chrome URL Blacklist: $($ChromePolicy.URLBlacklist)" "Browser"
            }
            if ($ChromePolicy.URLWhitelist) {
                Log "Chrome URL Whitelist: $($ChromePolicy.URLWhitelist)" "Browser"
            }
        }

        $EdgeBLKey = "HKCU:\Software\Policies\Microsoft\Edge"
        if (Test-Path $EdgeBLKey) {
            $EdgePolicy = Get-ItemProperty -Path $EdgeBLKey -ErrorAction SilentlyContinue
            if ($EdgePolicy.URLBlacklist) {
                Log "Edge URL Blacklist: $($EdgePolicy.URLBlacklist)" "Browser"
            }
            if ($EdgePolicy.URLAllowlist) {
                Log "Edge URL Whitelist: $($EdgePolicy.URLAllowlist)" "Browser"
            }
        }

        # For Firefox, you'd parse prefs.js or user.js for lines like:
        #  user_pref("extensions.blocklist.enabled", true);
        #  user_pref("extensions.blocklist.url", "...")
        #  Or custom about:config entries for allow/deny lists
    } catch {
        Log "Error retrieving browser whitelists/blacklists: $($_.Exception.Message) [ERROR]" "Browser"
    }

    ############################################################################
    # EXTRACT BROWSER HISTORY
    ############################################################################
    Log "" "Browser"
    Log "=== Extracting Browser History to C:\tmp\Files\BrowserHistory ===" "Browser"
    try {
        # This approach enumerates all local user profiles and copies known DB files.
        # Adjust as needed for multi-user environments.

        $UserDirs = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -notin @("All Users","Default","Default User","Public") }

        foreach ($ud in $UserDirs) {
            $UserName = $ud.Name
            $UserPath = $ud.FullName

            # 1) Internet Explorer History
            #    Typically older Internet Explorer used "index.dat" or "History.IE5" but modern
            #    IE/Edge integration is messy. You could copy the entire History folder if found.
            $IEHistoryFolder = Join-Path $UserPath "AppData\Local\Microsoft\Windows\History"
            if (Test-Path $IEHistoryFolder) {
                $IECopyPath = Join-Path $BrowserHistoryPath "IE_$UserName"
                Copy-Item -Path $IEHistoryFolder -Destination $IECopyPath -Recurse -Force -ErrorAction SilentlyContinue
                Log "Copied IE History from $IEHistoryFolder to $IECopyPath" "Browser"
            }

            # 2) Edge (Chromium) - History is stored in a SQLite DB: 
            #    C:\Users\<User>\AppData\Local\Microsoft\Edge\User Data\Default\History
            $EdgeHistoryFile = Join-Path $UserPath "AppData\Local\Microsoft\Edge\User Data\Default\History"
            if (Test-Path $EdgeHistoryFile) {
                $EdgeCopyDir = Join-Path $BrowserHistoryPath "Edge_$UserName"
                if (-not (Test-Path $EdgeCopyDir)) { New-Item -ItemType Directory -Path $EdgeCopyDir | Out-Null }
                Copy-Item -Path $EdgeHistoryFile -Destination (Join-Path $EdgeCopyDir "History") -Force -ErrorAction SilentlyContinue
                Log "Copied Edge History from $EdgeHistoryFile to $EdgeCopyDir" "Browser"
            }

            # 3) Chrome - Similar to Edge: 
            #    C:\Users\<User>\AppData\Local\Google\Chrome\User Data\Default\History
            $ChromeHistoryFile = Join-Path $UserPath "AppData\Local\Google\Chrome\User Data\Default\History"
            if (Test-Path $ChromeHistoryFile) {
                $ChromeCopyDir = Join-Path $BrowserHistoryPath "Chrome_$UserName"
                if (-not (Test-Path $ChromeCopyDir)) { New-Item -ItemType Directory -Path $ChromeCopyDir | Out-Null }
                Copy-Item -Path $ChromeHistoryFile -Destination (Join-Path $ChromeCopyDir "History") -Force -ErrorAction SilentlyContinue
                Log "Copied Chrome History from $ChromeHistoryFile to $ChromeCopyDir" "Browser"
            }

            # 4) Firefox - The browsing history & bookmarks are in places.sqlite:
            #    C:\Users\<User>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>\places.sqlite
            $FFProfilePath = Join-Path $UserPath "AppData\Roaming\Mozilla\Firefox\Profiles"
            if (Test-Path $FFProfilePath) {
                $Profiles = Get-ChildItem $FFProfilePath -Directory -ErrorAction SilentlyContinue
                foreach ($ffp in $Profiles) {
                    $PlacesFile = Join-Path $ffp.FullName "places.sqlite"
                    if (Test-Path $PlacesFile) {
                        $FFCopyDir = Join-Path $BrowserHistoryPath ("Firefox_{0}_{1}" -f $UserName, $ffp.Name)
                        if (-not (Test-Path $FFCopyDir)) { New-Item -ItemType Directory -Path $FFCopyDir | Out-Null }
                        Copy-Item -Path $PlacesFile -Destination (Join-Path $FFCopyDir "places.sqlite") -Force -ErrorAction SilentlyContinue
                        Log "Copied Firefox History from $PlacesFile to $FFCopyDir" "Browser"
                    }
                }
            }
        }
    } catch {
        Log "Error copying browser history: $($_.Exception.Message) [ERROR]" "Browser"
    }

} catch {
    Log "Error retrieving browser security settings: $($_.Exception.Message) [ERROR]" "Browser"
}

###############################################################################
# REMOVABLE STORAGE & USB POLICY
###############################################################################
LogSection "REMOVABLE STORAGE & USB POLICY"
try {
    ############################################################################
    # 1) LIST USB DEVICES
    ############################################################################
    Log "=== Listing USB Devices ===" "USB"

    try {
        # Enumerate PnP devices with a USB PNPClass
        $USBDevices = Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPClass -eq "USB" }
        if ($USBDevices) {
            foreach ($device in $USBDevices) {
                Log "USB Device: $($device.Name), Manufacturer: $($device.Manufacturer), Status: $($device.Status)" "USB"
            }
        } else {
            Log "No USB devices found or unable to query." "USB"
        }
    } catch {
        Log "Error enumerating USB devices: $($_.Exception.Message) [ERROR]" "USB"
    }

    ############################################################################
    # 2) REGISTRY CHECK: USBSTOR (Enable/Disable)
    ############################################################################
    Log "" "USB"
    Log "=== Checking UsbStor Service (Enable/Disable) ===" "USB"

    try {
        # If 'Start' is 3, USB storage is enabled. If 'Start' is 4, it’s disabled.
        $UsbStorPath = "HKLM:\System\CurrentControlSet\Services\UsbStor"
        if (Test-Path $UsbStorPath) {
            $UsbStorStart = (Get-ItemProperty -Path $UsbStorPath -Name "Start" -ErrorAction SilentlyContinue).Start
            switch ($UsbStorStart) {
                3 { Log "UsbStor Service: ENABLED (Start=3)" "USB" }
                4 { Log "UsbStor Service: DISABLED (Start=4)" "USB" }
                default { Log "UsbStor Service: Start=$UsbStorStart (unrecognized)" "USB" }
            }
        } else {
            Log "UsbStor registry key not found: $UsbStorPath" "USB"
        }
    } catch {
        Log "Error checking UsbStor service settings: $($_.Exception.Message) [ERROR]" "USB"
    }

    ############################################################################
    # 3) GPO/REGISTRY CHECK: REMOVABLE STORAGE DEVICES
    ############################################################################
    Log "" "USB"
    Log "=== Checking Removable Storage Policies ===" "USB"

    try {
        # Common path for removable storage GPO: 
        #   HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices
        # A subkey or value under here often stores Deny_Execute / Deny_Read / Deny_Write flags
        $RemovableStorageKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
        if (Test-Path $RemovableStorageKey) {
            $StorageValues = Get-ItemProperty -Path $RemovableStorageKey -ErrorAction SilentlyContinue
            foreach ($val in $StorageValues.PSObject.Properties) {
                if ($val.Name -notmatch "^PS") {
                    Log "RemovableStorageDevices Policy -> $($val.Name) = $($val.Value)" "USB"
                }
            }
        } else {
            Log "No RemovableStorageDevices policy key found at $RemovableStorageKey" "USB"
        }
    } catch {
        Log "Error checking removable storage policy: $($_.Exception.Message) [ERROR]" "USB"
    }

} catch {
    Log "Error during Removable Storage & USB Policy check: $($_.Exception.Message) [ERROR]" "Error"
}




###############################################################################
# SAVE RESULTS
###############################################################################
LogSection "SAVING AUDIT RESULTS"
try {
    $CSVData | Export-Csv -Path $CSVLogPath -NoTypeInformation -Force
    Log "Audit saved to CSV at $CSVLogPath" "General"
} catch {
    Log "Error saving audit to CSV: ${($_.Exception.Message)} [ERROR]" "Error"
}

###############################################################################
# FINALIZE AUDIT
###############################################################################
LogSection "AUDIT COMPLETED"
Log "Security audit completed. Log saved to $AuditLogPath." "General"
