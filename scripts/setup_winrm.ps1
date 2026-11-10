# =============================================================================
# setup_winrm.ps1: Enable WinRM for Ansible on Windows 10/11
# =============================================================================
# Run as Administrator on each Windows host:
# (Alternative: Ansible over OpenSSH for Windows, supported since ansible-core 2.18.)
#   powershell -ExecutionPolicy Bypass -File setup_winrm.ps1
# =============================================================================

Write-Host "=== Configuring WinRM for Ansible ===" -ForegroundColor Cyan

# 1. Enable WinRM
Write-Host "[1/6] Enabling WinRM service..." -ForegroundColor Yellow
Enable-PSRemoting -Force -SkipNetworkProfileCheck

# 2. Configure HTTPS listener with self-signed certificate
Write-Host "[2/6] Creating self-signed certificate for HTTPS..." -ForegroundColor Yellow
$hostname = $env:COMPUTERNAME
$cert = New-SelfSignedCertificate `
    -DnsName $hostname `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -NotAfter (Get-Date).AddYears(5)

# Remove existing HTTPS listener if present
$existingListener = Get-ChildItem WSMan:\localhost\Listener | Where-Object {
    $_.Keys -contains "Transport=HTTPS"
}
if ($existingListener) {
    Remove-Item -Path "WSMan:\localhost\Listener\$($existingListener.Name)" -Recurse -Force
}

# Create HTTPS listener
New-Item -Path WSMan:\localhost\Listener `
    -Transport HTTPS `
    -Address * `
    -CertificateThumbPrint $cert.Thumbprint `
    -Force

# 3. Configure authentication
Write-Host "[3/6] Configuring authentication..." -ForegroundColor Yellow
# Basic auth stays off: the inventory uses NTLM (or Kerberos in a domain).
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false
Set-Item -Path WSMan:\localhost\Service\Auth\Negotiate -Value $true
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false

# 4. Configure firewall
Write-Host "[4/6] Configuring firewall rules..." -ForegroundColor Yellow
$firewallParams = @{
    DisplayName = "WinRM HTTPS (Ansible)"
    Direction   = "Inbound"
    LocalPort   = 5986
    Protocol    = "TCP"
    Action      = "Allow"
    Profile     = "Domain,Private"
}

# Remove existing rule if present
$existing = Get-NetFirewallRule -DisplayName $firewallParams.DisplayName -ErrorAction SilentlyContinue
if ($existing) {
    Remove-NetFirewallRule -DisplayName $firewallParams.DisplayName
}
New-NetFirewallRule @firewallParams

# 5. Increase memory and shell limits
Write-Host "[5/6] Adjusting resource limits..." -ForegroundColor Yellow
Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB 1024
Set-Item WSMan:\localhost\Service\MaxConcurrentOperationsPerUser 20
Set-Item WSMan:\localhost\Shell\MaxShellsPerUser 20

# 6. Restart service
Write-Host "[6/6] Restarting WinRM..." -ForegroundColor Yellow
Restart-Service WinRM

# Verification
Write-Host ""
Write-Host "=== Verification ===" -ForegroundColor Green
Write-Host "Active listeners:" -ForegroundColor Yellow
winrm enumerate winrm/config/Listener

Write-Host ""
Write-Host "Test connection from the Ansible server:" -ForegroundColor Yellow
Write-Host "  ansible windows_servers -m win_ping -i inventory/hosts.yml" -ForegroundColor White
Write-Host ""
Write-Host "✅ WinRM configured successfully on $hostname" -ForegroundColor Green
