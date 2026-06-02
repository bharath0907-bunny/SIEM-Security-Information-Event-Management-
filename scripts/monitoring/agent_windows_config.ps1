# ==============================================================================
# Enterprise SIEM & Threat Detection Platform - Windows Agent Provisioner
# ==============================================================================
# Description: Installs and registers the Wazuh agent on Windows platforms,
#              subscribing to core security channels including PowerShell logging.
# Usage: Run in PowerShell as Administrator: .\agent_windows_config.ps1 -ManagerIP "YOUR_MANAGER_IP"
# ==============================================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$ManagerIP
)

# Check for administrative privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as an Administrator. Exiting."
    Exit
}

Write-Host "[*] Initializing Windows SIEM Agent Provisioner..." -ForegroundColor Green

# 1. Download and Install Wazuh Agent MSI if not already present
$AgentPath = "$env:TEMP\wazuh-agent.msi"
$InstallDir = "C:\Program Files (x86)\ossec-agent"

if (-not (Test-Path "$InstallDir\wazuh-agent.exe")) {
    Write-Host "[*] Downloading Wazuh Agent MSI installer..." -ForegroundColor Green
    $DownloaderURL = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.2-1.msi"
    Invoke-WebRequest -Uri $DownloaderURL -OutFile $AgentPath -UseBasicParsing
    
    Write-Host "[*] Executing quiet installation targeting manager: $ManagerIP" -ForegroundColor Green
    $Arguments = "/q /i `"$AgentPath`" WAZUH_MANAGER=`"$ManagerIP`""
    Start-Process msiexec.exe -ArgumentList $Arguments -Wait -NoNewWindow
    Write-Host "[*] Wazuh Agent installation completed." -ForegroundColor Green
} else {
    Write-Host "[*] Wazuh Agent is already installed." -ForegroundColor Yellow
}

# 2. Configure ossec.conf on Windows client
$ConfPath = "$InstallDir\ossec.conf"
if (Test-Path $ConfPath) {
    Write-Host "[*] Creating backup of default client configuration..." -ForegroundColor Green
    Copy-Item $ConfPath "$ConfPath.bak" -Force

    Write-Host "[*] Writing custom Windows event monitoring rules to config..." -ForegroundColor Green
    $xmlContent = @"
<ossec_config>
  <client>
    <server>
      <address>$ManagerIP</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <crypto_method>aes</crypto_method>
  </client>

  <!-- Windows Event Log collection -->
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Windows PowerShell Script Block Logging Ingestion -->
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
    <query>Event[System[EventID=4104]]</query>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

</ossec_config>
"@
    Set-Content -Path $ConfPath -Value $xmlContent -Force
    Write-Host "[*] Configuration updated successfully." -ForegroundColor Green
}

# 3. Restart Agent Service
Write-Host "[*] Starting/Restarting Wazuh Agent Windows Service..." -ForegroundColor Green
Restart-Service -Name "Wazuh" -Force
Write-Host "[*] Provisioning sequence complete! Agent active and communicating." -ForegroundColor Green
