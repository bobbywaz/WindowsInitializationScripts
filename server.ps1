#  Always use Powershell on Win+X
"$registryPath = ""HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced""
$Name = ""DontUsePowerShellOnWinX""
$value = ""0""
IF(!(Test-Path $registryPath)) {New-Item -Path $registryPath -Force | Out-Null New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null} ELSE {New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null}
Stop-Process -ProcessName explorer"
#  Install choco
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
#  Disable choco confirmations
choco feature enable -n=allowGlobalConfirmation
#  Show all tray icons, folders, file extensions
"New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name EnableAutoTray -PropertyType DWORD -Value 0
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneShowAllFolders -PropertyType DWORD -Value 1
New-ItemProperty -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneShowAllFolders -PropertyType DWORD -Value 1
New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -PropertyType DWORD -Value 0
Stop-Process -ProcessName explorer"
#  Enable PowerShell ISE
Import-module servermanager; add-windowsfeature powershell-ise
#  Block Server Manager from Startup
Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask -Verbose
#Set Timezone
Set-TimeZone -Name "Eastern Standard Time"
# Install Apps in Choco
choco install googlechrome teamviewer 7zip notepadplusplus winscp filezilla putty vmware-tools beyondcompare speedtest -y
#  Install SSH (disabled by default)
# Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0; Start-Service sshd; Set-Service -Name sshd -StartupType 'Automatic'; Get-NetFirewallRule -Name *ssh*; New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
#  Configure SSH (disabled by default)
# "$theCurrentPath=(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
# $$theUpdatedPath=$theCurrentPath+';C:\Program Files\OpenSSH-Win64'
# '.\install-sshd.ps1'"
# netsh advfirewall firewall add rule name="OpenSSH Server" dir=in action=allow protocol=TCP localport=22; New-NetFirewallRule -DisplayName 'OpenSSH' -Profile @('Domain', 'Private') -Direction Inbound -Action Allow -Protocol TCP -LocalPort @('22')
#  Enable Remote Desktop
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 0; Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
#  Initialize RAW disks
"Get-Disk | Where-Object PartitionStyle -Eq ""RAW"" | Initialize-Disk -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -filesystem REFS -AllocationUnitSize 65536
#  Turn on shadow copies for C: Drive
$drive = ""c:""
vssadmin.exe add shadowstorage /for=$drive /on=$drive /maxsize=15%"
#  Set Display Resolution
Set-DisplayResolution -Width 1440 -Height 900 -Force
#  Install PSWindowsUpdates and do updates
Install-Module PSWindowsUpdate -Confirm; Get-WindowsUpdate -Confirm; Install-Windowsupdate -Confirm
#  Install RSAT
Install-WindowsFeature -IncludeAllSubFeature RSAT
Get-WindowsCapability -Online |? {$_.Name -like "*RSAT*" -and $_.State -eq "NotPresent"} | Add-WindowsCapability -Online

"Function DisableTelemetry {
    Write-Output ""Disabling Telemetry...""
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"" -Name ""AllowTelemetry"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"" -Name ""AllowTelemetry"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"" -Name ""AllowTelemetry"" -Type DWord -Value 0
    If (!(Test-Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"")) {
            New-Item -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"" -Force | Out-Null
    }
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"" -Name ""AllowBuildPreview"" -Type DWord -Value 0
    If (!(Test-Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"")) {
            New-Item -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"" -Force | Out-Null
    }
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"" -Name ""NoGenTicket"" -Type DWord -Value 1
    If (!(Test-Path ""HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"")) {
            New-Item -Path ""HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"" -Force | Out-Null
    }
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"" -Name ""CEIPEnable"" -Type DWord -Value 0
    If (!(Test-Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"")) {
            New-Item -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"" -Force | Out-Null
    }
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"" -Name ""AITEnable"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"" -Name ""DisableInventory"" -Type DWord -Value 1
    If (!(Test-Path ""HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP"")) {
            New-Item -Path ""HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP"" -Force | Out-Null
    }
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP"" -Name ""CEIPEnable"" -Type DWord -Value 0
    If (!(Test-Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"")) {
            New-Item -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"" -Force | Out-Null
    }
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"" -Name ""PreventHandwritingDataSharing"" -Type DWord -Value 1
    If (!(Test-Path ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput"")) {
            New-Item -Path ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput"" -Force | Out-Null
    }
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput"" -Name ""AllowLinguisticDataCollection"" -Type DWord -Value 0
    Disable-ScheduledTask -TaskName ""Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"" | Out-Null
    Disable-ScheduledTask -TaskName ""Microsoft\Windows\Application Experience\ProgramDataUpdater"" | Out-Null
    Disable-ScheduledTask -TaskName ""Microsoft\Windows\Autochk\Proxy"" | Out-Null
    Disable-ScheduledTask -TaskName ""Microsoft\Windows\Customer Experience Improvement Program\Consolidator"" | Out-Null
    Disable-ScheduledTask -TaskName ""Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"" | Out-Null
    Disable-ScheduledTask -TaskName ""Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"" | Out-Null
}



Function DisableWebSearch {
    Write-Output ""Disabling Bing Search in Start Menu...""
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"" -Name ""BingSearchEnabled"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"" -Name ""CortanaConsent"" -Type DWord -Value 0
    If (!(Test-Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"")) {
            New-Item -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"" -Force | Out-Null
    }
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"" -Name ""DisableWebSearch"" -Type DWord -Value 1
}


Function DisableAppSuggestions {
    Write-Output ""Disabling Application suggestions...""
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" -Name ""ContentDeliveryAllowed"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" -Name ""OemPreInstalledAppsEnabled"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" -Name ""PreInstalledAppsEnabled"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" -Name ""PreInstalledAppsEverEnabled"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" -Name ""SilentInstalledAppsEnabled"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" -Name ""SubscribedContent-310093Enabled"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" -Name ""SubscribedContent-314559Enabled"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" -Name ""SubscribedContent-338387Enabled"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" -Name ""SubscribedContent-338388Enabled"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" -Name ""SubscribedContent-338389Enabled"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" -Name ""SubscribedContent-338393Enabled"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" -Name ""SubscribedContent-353694Enabled"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" -Name ""SubscribedContent-353696Enabled"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" -Name ""SubscribedContent-353698Enabled"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" -Name ""SystemPaneSuggestionsEnabled"" -Type DWord -Value 0
    If (!(Test-Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"")) {
            New-Item -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"" -Force | Out-Null
    }
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"" -Name ""DisableWindowsConsumerFeatures"" -Type DWord -Value 1
    If (!(Test-Path ""HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"")) {
            New-Item -Path ""HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"" -Force | Out-Null
    }
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"" -Name ""AllowSuggestedAppsInWindowsInkWorkspace"" -Type DWord -Value 0
    # Empty placeholder tile collection in registry cache and restart Start Menu process to reload the cache
    If ([System.Environment]::OSVersion.Version.Build -ge 17134) {
            $key = Get-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*windows.data.placeholdertilecollection\Current""
            Set-ItemProperty -Path $key.PSPath -Name ""Data"" -Type Binary -Value $key.Data[0..15]
            Stop-Process -Name ""ShellExperienceHost"" -Force -ErrorAction SilentlyContinue
    }
}


Function DisableFeedback {
    Write-Output ""Disabling Feedback...""
    If (!(Test-Path ""HKCU:\Software\Microsoft\Siuf\Rules"")) {
            New-Item -Path ""HKCU:\Software\Microsoft\Siuf\Rules"" -Force | Out-Null
    }
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Siuf\Rules"" -Name ""NumberOfSIUFInPeriod"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"" -Name ""DoNotShowFeedbackNotifications"" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName ""Microsoft\Windows\Feedback\Siuf\DmClient"" -ErrorAction SilentlyContinue | Out-Null
    Disable-ScheduledTask -TaskName ""Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"" -ErrorAction SilentlyContinue | Out-Null
}


Function DisableAdvertisingID {
    Write-Output ""Disabling Advertising ID...""
    If (!(Test-Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"")) {
            New-Item -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"" | Out-Null
    }
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"" -Name ""DisabledByGroupPolicy"" -Type DWord -Value 1
}


Function SetUACLow {
    Write-Output ""Lowering UAC level...""
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"" -Name ""ConsentPromptBehaviorAdmin"" -Type DWord -Value 0
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"" -Name ""PromptOnSecureDesktop"" -Type DWord -Value 0
}


Function SetCurrentNetworkPrivate {
    Write-Output ""Setting current network profile to private...""
    Set-NetConnectionProfile -NetworkCategory Private
}


Function SetUnknownNetworksPrivate {
    Write-Output ""Setting unknown networks profile to private...""
    If (!(Test-Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24"")) {
            New-Item -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24"" -Force | Out-Null
    }
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24"" -Name ""Category"" -Type DWord -Value 1
}


# Disable Autoplay
Function DisableAutoplay {
    Write-Output ""Disabling Autoplay...""
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"" -Name ""DisableAutoplay"" -Type DWord -Value 1
}


Function DisableAutorun {
    Write-Output ""Disabling Autorun for all drives...""
    If (!(Test-Path ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"")) {
            New-Item -Path ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"" | Out-Null
    }
    Set-ItemProperty -Path ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"" -Name ""NoDriveTypeAutoRun"" -Type DWord -Value 255
}

Function ShowSecondsInTaskbar {
    Write-Output ""Showing seconds in taskbar...""
    If (!(Test-Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"")) {
            New-Item -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"" | Out-Null
    }
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"" -Name ""ShowSecondsInSystemClock"" -Type DWord -Value 1
}

Function ShowKnownExtensions {
    Write-Output ""Showing known file extensions...""
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"" -Name ""HideFileExt"" -Type DWord -Value 0
}

Function ShowHiddenFiles {
    Write-Output ""Showing hidden files...""
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"" -Name ""Hidden"" -Type DWord -Value 1
}

# Hide Taskbar People icon
Function HideTaskbarPeopleIcon {
    Write-Output ""Hiding People icon...""
    If (!(Test-Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"")) {
            New-Item -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"" | Out-Null
    }
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"" -Name ""PeopleBand"" -Type DWord -Value 0
}

# Enable Dark Theme
Function EnableDarkTheme {
    Write-Output ""Enabling Dark Theme...""
    Set-ItemProperty -Path ""HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"" -Name ""AppsUseLightTheme"" -Type DWord -Value 0
}


# Enable verbose startup/shutdown status messages
Function EnableVerboseStatus {
    Write-Output ""Enabling verbose startup/shutdown status messages...""
    If ((Get-CimInstance -Class ""Win32_OperatingSystem"").ProductType -eq 1) {
            Set-ItemProperty -Path ""HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"" -Name ""VerboseStatus"" -Type DWord -Value 1
    } Else {
            Remove-ItemProperty -Path ""HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"" -Name ""VerboseStatus"" -ErrorAction SilentlyContinue
    }
}


DisableAutorun
DisableAutoplay
SetUnknownNetworksPrivate
#NetCurrentNetworkPrivate
DisableAdvertisingID
DisableTelemetry
DisableWebSearch
DisableAppSuggestions
DisableFeedback
SetUACLow
ShowSecondsInTaskbar
ShowKnownExtensions
ShowHiddenFiles
HideTaskbarPeopleIcon
EnableDarkTheme
EnableVerboseStatus

do
{
    Show-Menu
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
        '1' {
           'You chose option #1, Server 2016 Standard'
        dism /online /set-edition:ServerStandard /productkey:WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY /accepteula
        } '2' {
           'You chose option #2, Server 2019 Standard'
        dism /online /set-edition:ServerStandard /productkey:N69G4-B89J2-4G8F4-WWYCC-J464C /accepteula
        } '3' {
           'You chose option #3', Server 2019 Datacenter
        dism /online /set-edition:ServerStandard /productkey:WMDGN-G9PQG-XVVXX-R3X43-63DFG /accepteula
        }
    }
    pause
}
until ($selection -eq 'q')