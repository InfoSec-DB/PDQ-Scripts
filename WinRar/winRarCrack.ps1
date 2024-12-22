# Define the source path for the WinRAR registration key
$SourceKeyPath = "\\xCore-Admin01\PDQ Repos\Winrar\rarreg.key"

# Define the destination path
$AppDataPath = [Environment]::GetFolderPath("ApplicationData")
$WinRARPath = Join-Path -Path $AppDataPath -ChildPath "WinRAR"
$DestinationKeyPath = Join-Path -Path $WinRARPath -ChildPath "rarreg.key"

# Ensure the WinRAR directory exists
if (!(Test-Path -Path $WinRARPath)) {
    Write-Host "Creating directory: $WinRARPath"
    New-Item -Path $WinRARPath -ItemType Directory -Force
}

# Check if the registration key file exists in the source location
if (Test-Path -Path $SourceKeyPath) {
    # Copy the registration key to the destination
    try {
        Copy-Item -Path $SourceKeyPath -Destination $DestinationKeyPath -Force
        Write-Host "WinRAR registration key applied successfully."
    } catch {
        Write-Error "Failed to copy the registration key: $_"
        exit 1
    }
} else {
    Write-Error "Source key file not found: $SourceKeyPath"
    exit 1
}
