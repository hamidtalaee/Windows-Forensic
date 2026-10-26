#requires -Version 5.1

<#
.SYNOPSIS
Windows Forensic Triage - Read Only

.DESCRIPTION
Collects forensic triage information from a Windows endpoint.
No remediation / deletion / configuration changes are performed.

Sections:
01 - System Information
02 - Active Users
03 - Local Administrators
04 - Running Processes
05 - Network Connections
06 - Listening Ports
07 - Scheduled Tasks
08 - Services
09 - Registry Persistence
10 - Startup Items
11 - Security Events
12 - PowerShell Events
13 - Defender
14 - DNS / Hosts
15 - Suspicious Files
16 - Suspicious Findings
17 - Collection Errors
#>

$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# INITIALIZATION
# ============================================================

$StartTime = Get-Date
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Computer = $env:COMPUTERNAME

$BaseDir = Join-Path $env:USERPROFILE "Desktop\Forensic_$($Computer)_$Timestamp"
$RawDir = Join-Path $BaseDir "Raw"
$CsvDir = Join-Path $BaseDir "CSV"

New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null
New-Item -ItemType Directory -Path $RawDir -Force | Out-Null
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null

$Findings = New-Object System.Collections.Generic.List[object]
$Errors = New-Object System.Collections.Generic.List[object]

function Write-Section {
param([string]$Title)

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor DarkGray
Write-Host " $Title" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor DarkGray
}

function Save-CSV {
param(
[Parameter(Mandatory=$true)]$Data,
[Parameter(Mandatory=$true)][string]$Name
)

$Path = Join-Path $CsvDir $Name

if ($null -ne $Data) {
@($Data) | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

return $Path
}

function Save-JSON {
param(
[Parameter(Mandatory=$true)]$Data,
[Parameter(Mandatory=$true)][string]$Name
)

$Path = Join-Path $RawDir $Name

if ($null -ne $Data) {
$Data | ConvertTo-Json -Depth 8 | Out-File -FilePath $Path -Encoding UTF8
}

return $Path
}

function Add-Finding {
param(
[string]$Severity,
[string]$Category,
[string]$Title,
[string]$Evidence,
[string]$Explanation,
[string]$Recommendation
)

$Findings.Add([PSCustomObject]@{
Severity = $Severity
Category = $Category
Title = $Title
Evidence = $Evidence
Explanation = $Explanation
Recommendation = $Recommendation
})
}

function Add-CollectionError {
param(
[string]$Section,
[string]$ErrorText
)

$Errors.Add([PSCustomObject]@{
Time = Get-Date
Section = $Section
Error = $ErrorText
})
}

function Test-SuspiciousPath {
param([string]$Path)

if ([string]::IsNullOrWhiteSpace($Path)) {
return $false
}

$p = $Path.ToLower()

if ($p -match "\\appdata\\local\\temp\\") { return $true }
if ($p -match "\\windows\\temp\\") { return $true }
if ($p -match "\\users\\public\\") { return $true }
if ($p -match "\\programdata\\") { return $true }

return $false
}

# ============================================================
# 01 - SYSTEM INFORMATION
# ============================================================

Write-Section "01 - SYSTEM INFORMATION"

try {

$OS = Get-CimInstance Win32_OperatingSystem

$SystemInfo = [PSCustomObject]@{
ComputerName = $Computer
UserName = $env:USERNAME
Domain = $env:USERDOMAIN
OS = $OS.Caption
Version = $OS.Version
Build = $OS.BuildNumber
Architecture = $OS.OSArchitecture
InstallDate = $OS.InstallDate
LastBoot = $OS.LastBootUpTime
CollectionTime = $StartTime
}

$SystemInfo | Format-List
Save-CSV $SystemInfo "01_SystemInfo.csv" | Out-Null
Save-JSON $SystemInfo "01_SystemInfo.json" | Out-Null

}
catch {
Add-CollectionError "System Information" $_.Exception.Message
}

# ============================================================
# 02 - ACTIVE USERS
# ============================================================

Write-Section "02 - ACTIVE / LOGGED-ON USERS"

try {

$ActiveUsers = Get-CimInstance Win32_LoggedOnUser |
Select-Object Antecedent, Dependent -Unique

$ActiveUsers | Format-Table -AutoSize
Save-CSV $ActiveUsers "02_ActiveUsers.csv" | Out-Null

}
catch {
Add-CollectionError "Active Users" $_.Exception.Message
}

# ============================================================
# 03 - LOCAL ADMINISTRATORS
# ============================================================

Write-Section "03 - LOCAL ADMINISTRATORS"

try {

$Admins = Get-LocalGroupMember -Group "Administrators" |
Select-Object Name, ObjectClass, PrincipalSource

$Admins | Format-Table -AutoSize
Save-CSV $Admins "03_LocalAdministrators.csv" | Out-Null

foreach ($Admin in $Admins) {

if ($Admin.ObjectClass -eq "User") {

Add-Finding `
-Severity "REVIEW" `
-Category "Account" `
-Title "Local Administrator Account" `
-Evidence $Admin.Name `
-Explanation "The account has membership in the local Administrators group." `
-Recommendation "Verify that administrative privileges are required and that the account is authorized."
}
}

}
catch {
Add-CollectionError "Local Administrators" $_.Exception.Message
}

# ============================================================
# 04 - RUNNING PROCESSES
# ============================================================

Write-Section "04 - RUNNING PROCESSES"

try {

$Processes = Get-CimInstance Win32_Process |
Select-Object ProcessId,
ParentProcessId,
Name,
ExecutablePath,
CommandLine,
CreationDate

$Processes | Sort-Object Name | Format-Table Name,ProcessId,ParentProcessId -AutoSize

Save-CSV $Processes "04_Processes.csv" | Out-Null
Save-JSON $Processes "04_Processes.json" | Out-Null

foreach ($Process in $Processes) {

$Path = [string]$Process.ExecutablePath
$Cmd = [string]$Process.CommandLine
$Name = [string]$Process.Name

if (Test-SuspiciousPath $Path) {

Add-Finding `
-Severity "MEDIUM" `
-Category "Process" `
-Title "Process Executing From Unusual Location" `
-Evidence "$Name | PID=$($Process.ProcessId) | $Path" `
-Explanation "Executable is running from a temporary, Public or otherwise commonly abused location." `
-Recommendation "Verify file origin, digital signature, hash, parent process and associated network activity."
}

if ($Cmd -match "(?i)EncodedCommand|FromBase64String|-enc\s") {

Add-Finding `
-Severity "HIGH" `
-Category "PowerShell" `
-Title "Encoded PowerShell Command" `
-Evidence $Cmd `
-Explanation "Encoded PowerShell parameters can be used to conceal command content." `
-Recommendation "Decode and inspect the command, parent process, user context and network connections."
}

if ($Cmd -match "(?i)DownloadString|DownloadFile|Invoke-WebRequest|Net\.WebClient|IEX\s*\(") {

Add-Finding `
-Severity "HIGH" `
-Category "Process" `
-Title "Potential PowerShell Download / Execution Pattern" `
-Evidence $Cmd `
-Explanation "The command line contains patterns commonly associated with downloading or dynamically executing content." `
-Recommendation "Review the complete command, destination URL/IP, parent process and user."
}
}

}
catch {
Add-CollectionError "Processes" $_.Exception.Message
}

# ============================================================
# 05 - NETWORK CONNECTIONS
# ============================================================

Write-Section "05 - TCP NETWORK CONNECTIONS"

try {

$Connections = Get-NetTCPConnection |
Select-Object LocalAddress,
LocalPort,
RemoteAddress,
RemotePort,
State,
OwningProcess

$Connections | Format-Table -AutoSize

Save-CSV $Connections "05_NetworkConnections.csv" | Out-Null
Save-JSON $Connections "05_NetworkConnections.json" | Out-Null

foreach ($Connection in $Connections) {

if ($Connection.State -eq "Established" -and
$Connection.RemoteAddress -notmatch "^(127\.|0\.0\.0\.0|::1$)") {

$Proc = Get-Process -Id $Connection.OwningProcess -ErrorAction SilentlyContinue

if ($Proc) {

$ProcPath = $null

try {
$ProcPath = $Proc.Path
}
catch {}

if (Test-SuspiciousPath $ProcPath) {

Add-Finding `
-Severity "HIGH" `
-Category "Network" `
-Title "Network Connection From Unusual Process Path" `
-Evidence "$($Connection.RemoteAddress):$($Connection.RemotePort) <- $($Proc.ProcessName) PID=$($Connection.OwningProcess) Path=$ProcPath" `
-Explanation "An active network connection belongs to a process executing from a commonly abused location." `
-Recommendation "Validate destination reputation, process signature, parent process and binary hash."
}
}
}
}

}
catch {
Add-CollectionError "Network Connections" $_.Exception.Message
}

# ============================================================
# 06 - LISTENING PORTS
# ============================================================

Write-Section "06 - LISTENING PORTS"

try {

$Listening = Get-NetTCPConnection -State Listen |
Select-Object LocalAddress,
LocalPort,
OwningProcess

$Listening | Format-Table -AutoSize

Save-CSV $Listening "06_ListeningPorts.csv" | Out-Null

foreach ($Port in $Listening) {

$KnownPorts = @(80,443,445,3389,5985,5986,22,23,21,25,53,135,139,1433,3306)

if ($KnownPorts -notcontains [int]$Port.LocalPort) {

Add-Finding `
-Severity "REVIEW" `
-Category "Network" `
-Title "Non-Standard Listening Port" `
-Evidence "Port $($Port.LocalPort) PID $($Port.OwningProcess)" `
-Explanation "A listening port was detected outside a small list of commonly used service ports." `
-Recommendation "Identify the owning process and verify whether the service is authorized."
}
}

}
catch {
Add-CollectionError "Listening Ports" $_.Exception.Message
}

# ============================================================
# 07 - SCHEDULED TASKS
# ============================================================

Write-Section "07 - SCHEDULED TASKS"

try {

$Tasks = Get-ScheduledTask |
ForEach-Object {

$Task = $_

$Info = $Task | Get-ScheduledTaskInfo

[PSCustomObject]@{
TaskName = $Task.TaskName
TaskPath = $Task.TaskPath
State = $Task.State
Author = $Task.Author
RunAsUser = $Task.Principal.UserId
RunLevel = $Task.Principal.RunLevel
LastRunTime = $Info.LastRunTime
NextRunTime = $Info.NextRunTime
Actions = (($Task.Actions | ForEach-Object {
"$($_.Execute) $($_.Arguments)"
}) -join " | ")
}
}

$Tasks | Format-Table TaskName,State,RunAsUser -AutoSize
Save-CSV $Tasks "07_ScheduledTasks.csv" | Out-Null

foreach ($Task in $Tasks) {

$Action = [string]$Task.Actions

if ($Action -match "(?i)powershell|wscript|cscript|mshta|rundll32|regsvr32|cmd\.exe") {

Add-Finding `
-Severity "HIGH" `
-Category "Persistence" `
-Title "Scheduled Task Uses Script / LOLBin" `
-Evidence "$($Task.TaskPath)$($Task.TaskName) -> $Action" `
-Explanation "The scheduled task invokes PowerShell, scripting engines or commonly abused Windows binaries." `
-Recommendation "Verify task owner, creation time, command line, script path and business purpose."
}

if ($Action -match "(?i)\\Temp\\|\\AppData\\|\\Users\\Public\\|ProgramData") {

Add-Finding `
-Severity "HIGH" `
-Category "Persistence" `
-Title "Scheduled Task Executes From Suspicious Path" `
-Evidence "$($Task.TaskName) -> $Action" `
-Explanation "The task references a location frequently used for temporary or user-writable execution." `
-Recommendation "Inspect the referenced file and verify its origin and signature."
}
}

}
catch {
Add-CollectionError "Scheduled Tasks" $_.Exception.Message
}

# ============================================================
# 08 - SERVICES
# ============================================================

Write-Section "08 - SERVICES"

try {

$Services = Get-CimInstance Win32_Service |
Select-Object Name,
DisplayName,
State,
StartMode,
StartName,
PathName

$Services | Format-Table Name,State,StartMode,StartName -AutoSize
Save-CSV $Services "08_Services.csv" | Out-Null

foreach ($Service in $Services) {

if (Test-SuspiciousPath $Service.PathName) {

Add-Finding `
-Severity "HIGH" `
-Category "Persistence" `
-Title "Service Executable From Unusual Path" `
-Evidence "$($Service.Name) -> $($Service.PathName)" `
-Explanation "The service executable references a commonly abused or user-writable location." `
-Recommendation "Verify service creation history, binary signature, hash and expected software owner."
}
}

}
catch {
Add-CollectionError "Services" $_.Exception.Message
}

# ============================================================
# 09 - REGISTRY PERSISTENCE
# ============================================================

Write-Section "09 - REGISTRY RUN KEYS"

try {

$RunLocations = @(
"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
"HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

$RegistryItems = New-Object System.Collections.Generic.List[object]

foreach ($Location in $RunLocations) {

if (Test-Path $Location) {

$Props = Get-ItemProperty $Location

foreach ($Property in $Props.PSObject.Properties) {

if ($Property.Name -notmatch "^PS") {

$RegistryItems.Add([PSCustomObject]@{
Location = $Location
Name = $Property.Name
Value = [string]$Property.Value
})
}
}
}
}

$RegistryItems | Format-Table -AutoSize
Save-CSV $RegistryItems "09_RegistryRunKeys.csv" | Out-Null

foreach ($Item in $RegistryItems) {

$Value = [string]$Item.Value

if ($Value -match "(?i)powershell|wscript|cscript|mshta|rundll32|regsvr32") {

Add-Finding `
-Severity "HIGH" `
-Category "Persistence" `
-Title "Suspicious Registry Persistence" `
-Evidence "$($Item.Location) -> $($Item.Name) = $Value" `
-Explanation "The Run key invokes a scripting engine or commonly abused Windows binary." `
-Recommendation "Verify the registry value, referenced file, user context and creation history."
}

if (Test-SuspiciousPath $Value) {

Add-Finding `
-Severity "HIGH" `
-Category "Persistence" `
-Title "Registry Persistence From Unusual Path" `
-Evidence "$($Item.Name) = $Value" `
-Explanation "Registry persistence references a user-writable or temporary location." `
-Recommendation "Inspect the referenced executable/script and validate its legitimacy."
}
}

}
catch {
Add-CollectionError "Registry Persistence" $_.Exception.Message
}

# ============================================================
# 10 - STARTUP ITEMS
# ============================================================

Write-Section "10 - STARTUP ITEMS"

try {

$Startup = Get-CimInstance Win32_StartupCommand |
Select-Object Name,
Command,
Location,
User

$Startup | Format-Table -AutoSize
Save-CSV $Startup "10_StartupItems.csv" | Out-Null

}
catch {
Add-CollectionError "Startup Items" $_.Exception.Message
}

# ============================================================
# 11 - SECURITY EVENTS
# ============================================================

Write-Section "11 - SECURITY EVENTS"

try {

$SecurityIDs = @(4624,4625,4672,4688,4720,4726,4732,4738,4740,1102)

$SecurityEvents = Get-WinEvent -FilterHashtable @{
LogName = "Security"
Id = $SecurityIDs
} -MaxEvents 500 |
Select-Object TimeCreated,
Id,
ProviderName,
LevelDisplayName,
Message

$SecurityEvents | Format-Table TimeCreated,Id,LevelDisplayName -AutoSize
Save-CSV $SecurityEvents "11_SecurityEvents.csv" | Out-Null

foreach ($Event in $SecurityEvents) {

if ($Event.Id -eq 1102) {

Add-Finding `
-Severity "CRITICAL" `
-Category "Security Log" `
-Title "Security Audit Log Cleared" `
-Evidence "Event ID 1102 at $($Event.TimeCreated)" `
-Explanation "Windows recorded that the Security audit log was cleared." `
-Recommendation "Investigate who cleared the log, surrounding events and possible anti-forensic activity."
}

if ($Event.Id -eq 4625) {

Add-Finding `
-Severity "REVIEW" `
-Category "Authentication" `
-Title "Failed Logon Event" `
-Evidence "4625 at $($Event.TimeCreated)" `
-Explanation "A failed authentication attempt was recorded." `
-Recommendation "Review source address, account, LogonType and frequency for brute-force indicators."
}

if ($Event.Id -eq 4672) {

Add-Finding `
-Severity "REVIEW" `
-Category "Privilege" `
-Title "Special Privileges Assigned" `
-Evidence "4672 at $($Event.TimeCreated)" `
-Explanation "A logon received sensitive administrative privileges." `
-Recommendation "Verify the account and determine whether the privileged logon was expected."
}
}

}
catch {
Add-CollectionError "Security Events" $_.Exception.Message
}

# ============================================================
# 12 - POWERSHELL EVENTS
# ============================================================

Write-Section "12 - POWERSHELL EVENTS"

try {

$PSLogs = @(
"Microsoft-Windows-PowerShell/Operational"
)

$PowerShellEvents = foreach ($Log in $PSLogs) {

Get-WinEvent -LogName $Log -MaxEvents 300 |
Select-Object TimeCreated,
Id,
LevelDisplayName,
Message
}

$PowerShellEvents | Format-Table TimeCreated,Id -AutoSize
Save-CSV $PowerShellEvents "12_PowerShellEvents.csv" | Out-Null

foreach ($Event in $PowerShellEvents) {

if ($Event.Message -match "(?i)EncodedCommand|FromBase64String|DownloadString|Invoke-WebRequest|IEX\s*\(") {

Add-Finding `
-Severity "HIGH" `
-Category "PowerShell" `
-Title "Suspicious PowerShell Activity" `
-Evidence $Event.Message `
-Explanation "PowerShell telemetry contains command patterns frequently associated with obfuscation, downloading or dynamic execution." `
-Recommendation "Correlate with process creation, user account, parent process and network connections."
}
}

}
catch {
Add-CollectionError "PowerShell Events" $_.Exception.Message
}

# ============================================================
# 13 - WINDOWS DEFENDER
# ============================================================

Write-Section "13 - WINDOWS DEFENDER"

try {

$DefenderStatus = Get-MpComputerStatus |
Select-Object AMServiceEnabled,
AntivirusEnabled,
AntispywareEnabled,
RealTimeProtectionEnabled,
BehaviorMonitorEnabled,
IoavProtectionEnabled,
NISEnabled,
AntivirusSignatureVersion,
AntivirusSignatureLastUpdated

$DefenderStatus | Format-List
Save-CSV $DefenderStatus "13_DefenderStatus.csv" | Out-Null

$DefenderEvents = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 300 |
Select-Object TimeCreated,Id,LevelDisplayName,Message

Save-CSV $DefenderEvents "13_DefenderEvents.csv" | Out-Null

foreach ($Event in $DefenderEvents) {

if ($Event.Id -in @(1116,1117,1118,1119)) {

Add-Finding `
-Severity "HIGH" `
-Category "Defender" `
-Title "Windows Defender Detection / Action Event" `
-Evidence "Event ID $($Event.Id) at $($Event.TimeCreated)" `
-Explanation "Windows Defender recorded a malware detection or related security action." `
-Recommendation "Review the detection name, affected file, process and remediation result."
}
}

}
catch {
Add-CollectionError "Windows Defender" $_.Exception.Message
}

# ============================================================
# 14 - DNS / HOSTS
# ============================================================

Write-Section "14 - DNS / HOSTS"

try {

$DnsCache = Get-DnsClientCache |
Select-Object Entry,
RecordName,
RecordType,
Status,
Data

Save-CSV $DnsCache "14_DNSCache.csv" | Out-Null

$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"

if (Test-Path $HostsPath) {

$HostsContent = Get-Content $HostsPath

$HostsContent |
Where-Object { $_ -and $_ -notmatch "^\s*#" } |
Out-File (Join-Path $RawDir "14_Hosts.txt") -Encoding UTF8
}

}
catch {
Add-CollectionError "DNS / Hosts" $_.Exception.Message
}

# ============================================================
# 15 - SUSPICIOUS FILES
# ============================================================

Write-Section "15 - SUSPICIOUS FILES"

try {

$SearchPaths = @(
"$env:TEMP",
"$env:WINDIR\Temp",
"$env:USERPROFILE\AppData\Roaming",
"$env:USERPROFILE\AppData\Local",
"$env:PUBLIC"
)

$SuspiciousFiles = New-Object System.Collections.Generic.List[object]

foreach ($SearchPath in $SearchPaths) {

if (Test-Path $SearchPath) {

Get-ChildItem -Path $SearchPath -File -Recurse -ErrorAction SilentlyContinue |
Where-Object {
$_.Extension -in @(".exe",".dll",".ps1",".vbs",".js",".jse",".hta",".bat",".cmd")
} |
Where-Object {
$_.LastWriteTime -gt (Get-Date).AddDays(-7)
} |
Select-Object -First 300 |
ForEach-Object {

$Hash = $null

try {
$Hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
}
catch {}

$SuspiciousFiles.Add([PSCustomObject]@{
FullName = $_.FullName
Length = $_.Length
CreationTime = $_.CreationTime
LastWriteTime = $_.LastWriteTime
Extension = $_.Extension
SHA256 = $Hash
})
}
}
}

$SuspiciousFiles |
Sort-Object LastWriteTime -Descending |
Format-Table FullName,LastWriteTime,Extension,SHA256 -AutoSize

Save-CSV $SuspiciousFiles "15_SuspiciousFiles.csv" | Out-Null

foreach ($File in $SuspiciousFiles) {

Add-Finding `
-Severity "REVIEW" `
-Category "File" `
-Title "Recently Modified Executable / Script" `
-Evidence "$($File.FullName) | SHA256=$($File.SHA256)" `
-Explanation "An executable or script was recently modified in a user-writable or temporary location." `
-Recommendation "Validate digital signature, file origin, hash reputation and process execution history."
}

}
catch {
Add-CollectionError "Suspicious Files" $_.Exception.Message
}

# ============================================================
# 16 - ADDITIONAL SUSPICIOUS PROCESS PATTERNS
# ============================================================

Write-Section "16 - SUSPICIOUS FINDINGS"

try {

$InterestingProcesses = $Processes |
Where-Object {
$_.Name -match "(?i)powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin"
}

foreach ($P in $InterestingProcesses) {

Add-Finding `
-Severity "REVIEW" `
-Category "LOLBin" `
-Title "Potentially Interesting Windows Utility" `
-Evidence "$($P.Name) PID=$($P.ProcessId) CMD=$($P.CommandLine)" `
-Explanation "The process is a scripting engine or Windows utility that can be legitimate but is also commonly investigated during incident response." `
-Recommendation "Correlate with parent process, user, command line, execution time and network activity."
}

}
catch {
Add-CollectionError "Suspicious Findings" $_.Exception.Message
}

# ============================================================
# SAVE FINDINGS
# ============================================================

$FindingsPath = Save-CSV $Findings "16_SuspiciousFindings.csv"
$ErrorsPath = Save-CSV $Errors "17_CollectionErrors.csv"

# ============================================================
# HTML REPORT
# ============================================================

Write-Section "GENERATING HTML REPORT"

$CriticalCount = @($Findings | Where-Object Severity -eq "CRITICAL").Count
$HighCount = @($Findings | Where-Object Severity -eq "HIGH").Count
$MediumCount = @($Findings | Where-Object Severity -eq "MEDIUM").Count
$ReviewCount = @($Findings | Where-Object Severity -eq "REVIEW").Count

$ReportPath = Join-Path $BaseDir "Forensic_Report.html"

function HtmlEncode {
param([string]$Text)

if ($null -eq $Text) {
return ""
}

return [System.Net.WebUtility]::HtmlEncode($Text)
}

$FindingRows = ""

foreach ($F in $Findings) {

$FindingRows += @"
<tr>
<td>$(HtmlEncode $F.Severity)</td>
<td>$(HtmlEncode $F.Category)</td>
<td>$(HtmlEncode $F.Title)</td>
<td><pre>$(HtmlEncode $F.Evidence)</pre></td>
<td>$(HtmlEncode $F.Explanation)</td>
<td>$(HtmlEncode $F.Recommendation)</td>
</tr>
"@
}

$Report = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">

<title>Windows Forensic Triage - $Computer</title>

<style>

body {
font-family: Arial, sans-serif;
background:#111;
color:#ddd;
margin:30px;
}

h1 {
color:#00d084;
}

h2 {
color:#55d6be;
border-bottom:1px solid #444;
padding-bottom:8px;
}

.card {
display:inline-block;
background:#1d1d1d;
padding:20px;
margin:8px;
min-width:140px;
border-radius:8px;
}

.number {
font-size:30px;
font-weight:bold;
}

table {
width:100%;
border-collapse:collapse;
background:#181818;
}

th {
background:#222;
color:#00d084;
padding:10px;
text-align:left;
}

td {
border:1px solid #333;
padding:8px;
vertical-align:top;
}

pre {
white-space:pre-wrap;
word-break:break-word;
font-family:Consolas,monospace;
}

.critical {
color:#ff4444;
font-weight:bold;
}

.high {
color:#ff9933;
font-weight:bold;
}

.review {
color:#ffd166;
font-weight:bold;
}

.footer {
margin-top:30px;
color:#888;
}

</style>
</head>

<body>

<h1>WINDOWS FORENSIC TRIAGE REPORT</h1>

<p>
<b>Computer:</b> $(HtmlEncode $Computer)<br>
<b>User:</b> $(HtmlEncode "$env:USERDOMAIN\$env:USERNAME")<br>
<b>Collection:</b> $(HtmlEncode $StartTime)<br>
<b>Report Generated:</b> $(HtmlEncode (Get-Date))
</p>

<h2>Finding Summary</h2>

<div class="card">
<div>CRITICAL</div>
<div class="number">$CriticalCount</div>
</div>

<div class="card">
<div>HIGH</div>
<div class="number">$HighCount</div>
</div>

<div class="card">
<div>MEDIUM</div>
<div class="number">$MediumCount</div>
</div>

<div class="card">
<div>REVIEW</div>
<div class="number">$ReviewCount</div>
</div>

<h2>Suspicious Findings</h2>

<table>

<tr>
<th>Severity</th>
<th>Category</th>
<th>Title</th>
<th>Evidence</th>
<th>Explanation</th>
<th>Recommended Review</th>
</tr>

$FindingRows

</table>

<h2>Collected Evidence</h2>

<ul>

<li>01_SystemInfo.csv</li>
<li>02_ActiveUsers.csv</li>
<li>03_LocalAdministrators.csv</li>
<li>04_Processes.csv</li>
<li>05_NetworkConnections.csv</li>
<li>06_ListeningPorts.csv</li>
<li>07_ScheduledTasks.csv</li>
<li>08_Services.csv</li>
<li>09_RegistryRunKeys.csv</li>
<li>10_StartupItems.csv</li>
<li>11_SecurityEvents.csv</li>
<li>12_PowerShellEvents.csv</li>
<li>13_DefenderStatus.csv</li>
<li>13_DefenderEvents.csv</li>
<li>14_DNSCache.csv</li>
<li>15_SuspiciousFiles.csv</li>
<li>16_SuspiciousFindings.csv</li>

</ul>

<h2>Collection Notes</h2>

<p>
This report is a forensic triage collection and does not constitute
a complete forensic image or definitive malware determination.
Findings require analyst validation and correlation with additional
telemetry such as EDR, SIEM, Sysmon and network logs.
</p>

<div class="footer">
Windows Forensic Triage
</div>

</body>
</html>
"@

$Report | Out-File -FilePath $ReportPath -Encoding UTF8

# ============================================================
# FINAL SUMMARY
# ============================================================

Write-Section "FORENSIC COLLECTION COMPLETED"

Write-Host ""
Write-Host "Computer : $Computer" -ForegroundColor White
Write-Host "Output : $BaseDir" -ForegroundColor Green
Write-Host "Report : $ReportPath" -ForegroundColor Green
Write-Host ""
Write-Host "CRITICAL : $CriticalCount" -ForegroundColor Red
Write-Host "HIGH : $HighCount" -ForegroundColor Yellow
Write-Host "MEDIUM : $MediumCount" -ForegroundColor Yellow
Write-Host "REVIEW : $ReviewCount" -ForegroundColor Cyan
Write-Host ""

Start-Process explorer.exe $BaseDir