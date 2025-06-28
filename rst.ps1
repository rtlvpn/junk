# Set output encoding to UTF-8
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Color definitions
$RED = "`e[31m"
$GREEN = "`e[32m"
$YELLOW = "`e[33m"
$BLUE = "`e[34m"
$NC = "`e[0m"

# Configuration file paths
$STORAGE_FILE = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
$BACKUP_DIR = "$env:APPDATA\Cursor\User\globalStorage\backups"

# New Cursor initialization function
function Cursor-Initialize {
    Write-Host "$GREEN[INFO]$NC Executing Cursor initialization cleanup..."
    $BASE_PATH = "$env:APPDATA\Cursor\User"

    $filesToDelete = @(
        (Join-Path -Path $BASE_PATH -ChildPath "globalStorage\\state.vscdb"),
        (Join-Path -Path $BASE_PATH -ChildPath "globalStorage\\state.vscdb.backup")
    )
    
    $folderToCleanContents = Join-Path -Path $BASE_PATH -ChildPath "History"
    $folderToDeleteCompletely = Join-Path -Path $BASE_PATH -ChildPath "workspaceStorage"

    Write-Host "$BLUE[DEBUG]$NC Base path: $BASE_PATH"

    # Delete specified files
    foreach ($file in $filesToDelete) {
        Write-Host "$BLUE[DEBUG]$NC Checking file: $file"
        if (Test-Path $file) {
            try {
                Remove-Item -Path $file -Force -ErrorAction Stop
                Write-Host "$GREEN[SUCCESS]$NC Deleted file: $file"
            }
            catch {
                Write-Host "$RED[ERROR]$NC Failed to delete file $file: $($_.Exception.Message)"
            }
        } else {
            Write-Host "$YELLOW[WARNING]$NC File does not exist, skipping deletion: $file"
        }
    }

    # Clear specified folder contents
    Write-Host "$BLUE[DEBUG]$NC Checking folder to clear contents: $folderToCleanContents"
    if (Test-Path $folderToCleanContents) {
        try {
            # Get child items for deletion to avoid deleting the History folder itself
            Get-ChildItem -Path $folderToCleanContents -Recurse | Remove-Item -Recurse -Force -ErrorAction Stop
            Write-Host "$GREEN[SUCCESS]$NC Cleared folder contents: $folderToCleanContents"
        }
        catch {
            Write-Host "$RED[ERROR]$NC Failed to clear folder contents $folderToCleanContents: $($_.Exception.Message)"
        }
    } else {
        Write-Host "$YELLOW[WARNING]$NC Folder does not exist, skipping clear: $folderToCleanContents"
    }

    # Delete specified folder and its contents
    Write-Host "$BLUE[DEBUG]$NC Checking folder to delete: $folderToDeleteCompletely"
    if (Test-Path $folderToDeleteCompletely) {
        try {
            Remove-Item -Path $folderToDeleteCompletely -Recurse -Force -ErrorAction Stop
            Write-Host "$GREEN[SUCCESS]$NC Deleted folder: $folderToDeleteCompletely"
        }
        catch {
            Write-Host "$RED[ERROR]$NC Failed to delete folder $folderToDeleteCompletely: $($_.Exception.Message)"
        }
    } else {
        Write-Host "$YELLOW[WARNING]$NC Folder does not exist, skipping deletion: $folderToDeleteCompletely"
    }

    Write-Host "$GREEN[INFO]$NC Cursor initialization cleanup completed."
    Write-Host "" # Add blank line to improve output formatting
}

# Check administrator privileges
function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($user)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host "$RED[ERROR]$NC Please run this script as administrator"
    Write-Host "Please right-click the script and select 'Run as administrator'"
    Read-Host "Press Enter to exit"
    exit 1
}

# Display Logo
Clear-Host
Write-Host @"

    ██████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗ 
   ██╔════╝██║   ██║██╔══██╗██╔════╝██╔═══██╗██╔══██╗
   ██║     ██║   ██║██████╔╝███████╗██║   ██║██████╔╝
   ██║     ██║   ██║██╔══██╗╚════██║██║   ██║██╔══██╗
   ╚██████╗╚██████╔╝██║  ██║███████║╚██████╔╝██║  ██║
    ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝

"@
Write-Host "$BLUE================================$NC"
Write-Host "$GREEN   Cursor Device ID Modification Tool          $NC"
Write-Host "$YELLOW  Follow WeChat Official Account【JianBingGuoZiJuanAI】 $NC"
Write-Host "$YELLOW  Let's exchange more Cursor tips and AI knowledge (script is free, follow the account to join groups for more tips and experts)  $NC"
Write-Host "$YELLOW  [IMPORTANT NOTE] This tool is free, if it helps you, please follow WeChat Official Account【JianBingGuoZiJuanAI】  $NC"
Write-Host ""
Write-Host "$YELLOW   [Small Advertisement]  Selling CursorPro education accounts with one-year warranty and three-month guarantee, contact me if needed (86), WeChat: JavaRookie666  $NC"
Write-Host "$BLUE================================$NC"

# Get and display Cursor version
function Get-CursorVersion {
    try {
        # Primary detection path
        $packagePath = "$env:LOCALAPPDATA\\Programs\\cursor\\resources\\app\\package.json"
        
        if (Test-Path $packagePath) {
            $packageJson = Get-Content $packagePath -Raw | ConvertFrom-Json
            if ($packageJson.version) {
                Write-Host "$GREEN[INFO]$NC Currently installed Cursor version: v$($packageJson.version)"
                return $packageJson.version
            }
        }

        # Alternative path detection
        $altPath = "$env:LOCALAPPDATA\\cursor\\resources\\app\\package.json"
        if (Test-Path $altPath) {
            $packageJson = Get-Content $altPath -Raw | ConvertFrom-Json
            if ($packageJson.version) {
                Write-Host "$GREEN[INFO]$NC Currently installed Cursor version: v$($packageJson.version)"
                return $packageJson.version
            }
        }

        Write-Host "$YELLOW[WARNING]$NC Unable to detect Cursor version"
        Write-Host "$YELLOW[TIP]$NC Please ensure Cursor is properly installed"
        return $null
    }
    catch {
        Write-Host "$RED[ERROR]$NC Failed to get Cursor version: $_"
        return $null
    }
}

# Get and display version information
$cursorVersion = Get-CursorVersion
Write-Host ""

Write-Host "$YELLOW[IMPORTANT NOTE]$NC Latest 1.0.x (supported)"
Write-Host ""

# Check and close Cursor processes
Write-Host "$GREEN[INFO]$NC Checking Cursor processes..."

function Get-ProcessDetails {
    param($processName)
    Write-Host "$BLUE[DEBUG]$NC Getting $processName process details:"
    Get-WmiObject Win32_Process -Filter "name='$processName'" | 
        Select-Object ProcessId, ExecutablePath, CommandLine | 
        Format-List
}

# Define maximum retry count and wait time
$MAX_RETRIES = 5
$WAIT_TIME = 1

# Handle process closure
function Close-CursorProcess {
    param($processName)
    
    $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($process) {
        Write-Host "$YELLOW[WARNING]$NC Found $processName is running"
        Get-ProcessDetails $processName
        
        Write-Host "$YELLOW[WARNING]$NC Attempting to close $processName..."
        Stop-Process -Name $processName -Force
        
        $retryCount = 0
        while ($retryCount -lt $MAX_RETRIES) {
            $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
            if (-not $process) { break }
            
            $retryCount++
            if ($retryCount -ge $MAX_RETRIES) {
                Write-Host "$RED[ERROR]$NC Unable to close $processName after $MAX_RETRIES attempts"
                Get-ProcessDetails $processName
                Write-Host "$RED[ERROR]$NC Please manually close the process and retry"
                Read-Host "Press Enter to exit"
                exit 1
            }
            Write-Host "$YELLOW[WARNING]$NC Waiting for process to close, attempt $retryCount/$MAX_RETRIES..."
            Start-Sleep -Seconds $WAIT_TIME
        }
        Write-Host "$GREEN[INFO]$NC $processName successfully closed"
    }
}

# Close all Cursor processes
Close-CursorProcess "Cursor"
Close-CursorProcess "cursor"

# Execute Cursor initialization cleanup
# Cursor-Initialize

# Create backup directory
if (-not (Test-Path $BACKUP_DIR)) {
    New-Item -ItemType Directory -Path $BACKUP_DIR | Out-Null
}

# Backup existing configuration
if (Test-Path $STORAGE_FILE) {
    Write-Host "$GREEN[INFO]$NC Backing up configuration file..."
    $backupName = "storage.json.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item $STORAGE_FILE "$BACKUP_DIR\$backupName"
}

# Generate new IDs
Write-Host "$GREEN[INFO]$NC Generating new IDs..."

# Add this function after color definitions
function Get-RandomHex {
    param (
        [int]$length
    )
    
    $bytes = New-Object byte[] ($length)
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $rng.GetBytes($bytes)
    $hexString = [System.BitConverter]::ToString($bytes) -replace '-',''
    $rng.Dispose()
    return $hexString
}

# Improved ID generation function
function New-StandardMachineId {
    $template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    $result = $template -replace '[xy]', {
        param($match)
        $r = [Random]::new().Next(16)
        $v = if ($match.Value -eq "x") { $r } else { ($r -band 0x3) -bor 0x8 }
        return $v.ToString("x")
    }
    return $result
}

# Use new function when generating IDs
$MAC_MACHINE_ID = New-StandardMachineId
$UUID = [System.Guid]::NewGuid().ToString()
# Convert auth0|user_ to hexadecimal of byte array
$prefixBytes = [System.Text.Encoding]::UTF8.GetBytes("auth0|user_")
$prefixHex = -join ($prefixBytes | ForEach-Object { '{0:x2}' -f $_ })
# Generate 32 bytes (64 hex characters) of random data as the random part of machineId
$randomPart = Get-RandomHex -length 32
$MACHINE_ID = "$prefixHex$randomPart"
$SQM_ID = "{$([System.Guid]::NewGuid().ToString().ToUpper())}"

# Add permission check before Update-MachineGuid function
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "$RED[ERROR]$NC Please run this script with administrator privileges"
    Start-Process powershell "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

function Update-MachineGuid {
    try {
        # Check if registry path exists, create if not
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Cryptography"
        if (-not (Test-Path $registryPath)) {
            Write-Host "$YELLOW[WARNING]$NC Registry path does not exist: $registryPath, creating..."
            New-Item -Path $registryPath -Force | Out-Null
            Write-Host "$GREEN[INFO]$NC Registry path created successfully"
        }

        # Get current MachineGuid, use empty string as default if not exists
        $originalGuid = ""
        try {
            $currentGuid = Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction SilentlyContinue
            if ($currentGuid) {
                $originalGuid = $currentGuid.MachineGuid
                Write-Host "$GREEN[INFO]$NC Current registry value:"
                Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography" 
                Write-Host "    MachineGuid    REG_SZ    $originalGuid"
            } else {
                Write-Host "$YELLOW[WARNING]$NC MachineGuid value does not exist, will create new value"
            }
        } catch {
            Write-Host "$YELLOW[WARNING]$NC Failed to get MachineGuid: $($_.Exception.Message)"
        }

        # Create backup directory (if not exists)
        if (-not (Test-Path $BACKUP_DIR)) {
            New-Item -ItemType Directory -Path $BACKUP_DIR -Force | Out-Null
        }

        # Create backup file (only when original value exists)
        if ($originalGuid) {
            $backupFile = "$BACKUP_DIR\MachineGuid_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
            $backupResult = Start-Process "reg.exe" -ArgumentList "export", "`"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography`"", "`"$backupFile`"" -NoNewWindow -Wait -PassThru
            
            if ($backupResult.ExitCode -eq 0) {
                Write-Host "$GREEN[INFO]$NC Registry key backed up to: $backupFile"
            } else {
                Write-Host "$YELLOW[WARNING]$NC Backup creation failed, continuing execution..."
            }
        }

        # Generate new GUID
        $newGuid = [System.Guid]::NewGuid().ToString()

        # Update or create registry value
        Set-ItemProperty -Path $registryPath -Name MachineGuid -Value $newGuid -Force -ErrorAction Stop
        
        # Verify update
        $verifyGuid = (Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction Stop).MachineGuid
        if ($verifyGuid -ne $newGuid) {
            throw "Registry verification failed: Updated value ($verifyGuid) does not match expected value ($newGuid)"
        }

        Write-Host "$GREEN[INFO]$NC Registry updated successfully:"
        Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
        Write-Host "    MachineGuid    REG_SZ    $newGuid"
        return $true
    }
    catch {
        Write-Host "$RED[ERROR]$NC Registry operation failed: $($_.Exception.Message)"
        
        # Try to restore backup (if exists)
        if (($backupFile -ne $null) -and (Test-Path $backupFile)) {
            Write-Host "$YELLOW[RESTORE]$NC Restoring from backup..."
            $restoreResult = Start-Process "reg.exe" -ArgumentList "import", "`"$backupFile`"" -NoNewWindow -Wait -PassThru
            
            if ($restoreResult.ExitCode -eq 0) {
                Write-Host "$GREEN[RESTORE SUCCESS]$NC Original registry value restored"
            } else {
                Write-Host "$RED[ERROR]$NC Restore failed, please manually import backup file: $backupFile"
            }
        } else {
            Write-Host "$YELLOW[WARNING]$NC Backup file not found or backup creation failed, cannot auto-restore"
        }
        return $false
    }
}

# Create or update configuration file
Write-Host "$GREEN[INFO]$NC Updating configuration..."

try {
    # Check if configuration file exists
    if (-not (Test-Path $STORAGE_FILE)) {
        Write-Host "$RED[ERROR]$NC Configuration file not found: $STORAGE_FILE"
        Write-Host "$YELLOW[TIP]$NC Please install and run Cursor at least once before using this script"
        Read-Host "Press Enter to exit"
        exit 1
    }

    # Read existing configuration file
    try {
        $originalContent = Get-Content $STORAGE_FILE -Raw -Encoding UTF8
        
        # Convert JSON string to PowerShell object
        $config = $originalContent | ConvertFrom-Json 

        # Backup current values
        $oldValues = @{
            'machineId' = $config.'telemetry.machineId'
            'macMachineId' = $config.'telemetry.macMachineId'
            'devDeviceId' = $config.'telemetry.devDeviceId'
            'sqmId' = $config.'telemetry.sqmId'
        }

        # Update specific values
        $config.'telemetry.machineId' = $MACHINE_ID
        $config.'telemetry.macMachineId' = $MAC_MACHINE_ID
        $config.'telemetry.devDeviceId' = $UUID
        $config.'telemetry.sqmId' = $SQM_ID

        # Convert updated object back to JSON and save
        $updatedJson = $config | ConvertTo-Json -Depth 10
        [System.IO.File]::WriteAllText(
            [System.IO.Path]::GetFullPath($STORAGE_FILE), 
            $updatedJson, 
            [System.Text.Encoding]::UTF8
        )
        Write-Host "$GREEN[INFO]$NC Successfully updated configuration file"
    } catch {
        # If error occurs, try to restore original content
        if ($originalContent) {
            [System.IO.File]::WriteAllText(
                [System.IO.Path]::GetFullPath($STORAGE_FILE), 
                $originalContent, 
                [System.Text.Encoding]::UTF8
            )
        }
        throw "JSON processing failed: $_"
    }
    
    # Directly execute MachineGuid update without asking
    Update-MachineGuid
    
    # Display results
    Write-Host ""
    Write-Host "$GREEN[INFO]$NC Updated configuration:"
    Write-Host "$BLUE[DEBUG]$NC machineId: $MACHINE_ID"
    Write-Host "$BLUE[DEBUG]$NC macMachineId: $MAC_MACHINE_ID"
    Write-Host "$BLUE[DEBUG]$NC devDeviceId: $UUID"
    Write-Host "$BLUE[DEBUG]$NC sqmId: $SQM_ID"

    # Display file tree structure
    Write-Host ""
    Write-Host "$GREEN[INFO]$NC File structure:"
    Write-Host "$BLUE$env:APPDATA\Cursor\User$NC"
    Write-Host "├── globalStorage"
    Write-Host "│   ├── storage.json (modified)"
    Write-Host "│   └── backups"

    # List backup files
    $backupFiles = Get-ChildItem "$BACKUP_DIR\*" -ErrorAction SilentlyContinue
    if ($backupFiles) {
        foreach ($file in $backupFiles) {
            Write-Host "│       └── $($file.Name)"
        }
    } else {
        Write-Host "│       └── (empty)"
    }

    # Display official account information
    Write-Host ""
    Write-Host "$GREEN================================$NC"
    Write-Host "$YELLOW  Follow WeChat Official Account【JianBingGuoZiJuanAI】to exchange more Cursor tips and AI knowledge (script is free, follow the account to join groups for more tips and experts)  $NC"
    Write-Host "$GREEN================================$NC"
    Write-Host ""
    Write-Host "$GREEN[INFO]$NC Please restart Cursor to apply the new configuration"
    Write-Host ""

    # Ask whether to disable auto-update
    Write-Host ""
    Write-Host "$YELLOW[QUESTION]$NC Do you want to disable Cursor auto-update feature?"
    Write-Host "0) No - Keep default settings (press Enter)"
    Write-Host "1) Yes - Disable auto-update"
    $choice = Read-Host "Please enter option (0)"

    if ($choice -eq "1") {
        Write-Host ""
        Write-Host "$GREEN[INFO]$NC Processing auto-update..."
        $updaterPath = "$env:LOCALAPPDATA\cursor-updater"

        # Define manual setup tutorial
        function Show-ManualGuide {
            Write-Host ""
            Write-Host "$YELLOW[WARNING]$NC Automatic setup failed, please try manual operation:"
            Write-Host "$YELLOW Manual disable update steps:$NC"
            Write-Host "1. Open PowerShell as administrator"
            Write-Host "2. Copy and paste the following commands:"
            Write-Host "$BLUE Command 1 - Delete existing directory (if exists):$NC"
            Write-Host "Remove-Item -Path `"$updaterPath`" -Force -Recurse -ErrorAction SilentlyContinue"
            Write-Host ""
            Write-Host "$BLUE Command 2 - Create blocking file:$NC"
            Write-Host "New-Item -Path `"$updaterPath`" -ItemType File -Force | Out-Null"
            Write-Host ""
            Write-Host "$BLUE Command 3 - Set read-only attribute:$NC"
            Write-Host "Set-ItemProperty -Path `"$updaterPath`" -Name IsReadOnly -Value `$true"
            Write-Host ""
            Write-Host "$BLUE Command 4 - Set permissions (optional):$NC"
            Write-Host "icacls `"$updaterPath`" /inheritance:r /grant:r `"`$($env:USERNAME):(R)`""
            Write-Host ""
            Write-Host "$YELLOW Verification method:$NC"
            Write-Host "1. Run command: Get-ItemProperty `"$updaterPath`""
            Write-Host "2. Confirm IsReadOnly attribute is True"
            Write-Host "3. Run command: icacls `"$updaterPath`""
            Write-Host "4. Confirm only read permissions"
            Write-Host ""
            Write-Host "$YELLOW[TIP]$NC Please restart Cursor after completion"
        }

        try {
            # Check if cursor-updater exists
            if (Test-Path $updaterPath) {
                # If it's a file, blocking update has already been created
                if ((Get-Item $updaterPath) -is [System.IO.FileInfo]) {
                    Write-Host "$GREEN[INFO]$NC Blocking update file already created, no need to block again"
                    return
                }
                # If it's a directory, try to delete
                else {
                    try {
                        Remove-Item -Path $updaterPath -Force -Recurse -ErrorAction Stop
                        Write-Host "$GREEN[INFO]$NC Successfully deleted cursor-updater directory"
                    }
                    catch {
                        Write-Host "$RED[ERROR]$NC Failed to delete cursor-updater directory"
                        Show-ManualGuide
                        return
                    }
                }
            }

            # Create blocking file
            try {
                New-Item -Path $updaterPath -ItemType File -Force -ErrorAction Stop | Out-Null
                Write-Host "$GREEN[INFO]$NC Successfully created blocking file"
            }
            catch {
                Write-Host "$RED[ERROR]$NC Failed to create blocking file"
                Show-ManualGuide
                return
            }

            # Set file permissions
            try {
                # Set read-only attribute
                Set-ItemProperty -Path $updaterPath -Name IsReadOnly -Value $true -ErrorAction Stop
                
                # Use icacls to set permissions
                $result = Start-Process "icacls.exe" -ArgumentList "`"$updaterPath`" /inheritance:r /grant:r `"$($env:USERNAME):(R)`"" -Wait -NoNewWindow -PassThru
                if ($result.ExitCode -ne 0) {
                    throw "icacls command failed"
                }
                
                Write-Host "$GREEN[INFO]$NC Successfully set file permissions"
            }
            catch {
                Write-Host "$RED[ERROR]$NC Failed to set file permissions"
                Show-ManualGuide
                return
            }

            # Verify settings
            try {
                $fileInfo = Get-ItemProperty $updaterPath
                if (-not $fileInfo.IsReadOnly) {
                    Write-Host "$RED[ERROR]$NC Verification failed: File permission settings may not have taken effect"
                    Show-ManualGuide
                    return
                }
            }
            catch {
                Write-Host "$RED[ERROR]$NC Failed to verify settings"
                Show-ManualGuide
                return
            }

            Write-Host "$GREEN[INFO]$NC Successfully disabled auto-update"
        }
        catch {
            Write-Host "$RED[ERROR]$NC Unknown error occurred: $_"
            Show-ManualGuide
        }
    }
    else {
        Write-Host "$GREEN[INFO]$NC Keeping default settings, no changes made"
    }

    # Keep valid registry update
    Update-MachineGuid

} catch {
    Write-Host "$RED[ERROR]$NC Main operation failed: $_"
    Write-Host "$YELLOW[TRYING]$NC Using alternative method..."
    
    try {
        # Alternative method: using Add-Content
        $tempFile = [System.IO.Path]::GetTempFileName()
        $config | ConvertTo-Json | Set-Content -Path $tempFile -Encoding UTF8
        Copy-Item -Path $tempFile -Destination $STORAGE_FILE -Force
        Remove-Item -Path $tempFile
        Write-Host "$GREEN[INFO]$NC Successfully wrote configuration using alternative method"
    } catch {
        Write-Host "$RED[ERROR]$NC All attempts failed"
        Write-Host "Error details: $_"
        Write-Host "Target file: $STORAGE_FILE"
        Write-Host "Please ensure you have sufficient permissions to access the file"
        Read-Host "Press Enter to exit"
        exit 1
    }
}

Write-Host ""
Read-Host "Press Enter to exit"
exit 0

# Modify file writing section
function Write-ConfigFile {
    param($config, $filePath)
    
    try {
        # Use UTF8 without BOM encoding
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        $jsonContent = $config | ConvertTo-Json -Depth 10
        
        # Unify using LF line breaks
        $jsonContent = $jsonContent.Replace("`r`n", "`n")
        
        [System.IO.File]::WriteAllText(
            [System.IO.Path]::GetFullPath($filePath),
            $jsonContent,
            $utf8NoBom
        )
        
        Write-Host "$GREEN[INFO]$NC Successfully wrote configuration file (UTF8 without BOM)"
    }
    catch {
        throw "Failed to write configuration file: $_"
    }
}
