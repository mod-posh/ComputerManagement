Function Get-InvalidLogonAttempt {
 [cmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-InvalidLogonAttempt.md#get-invalidlogonattempt')]
 Param
 (
  [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
  $ComputerName,
  $LogName = "Security",
  $EventID = 4625
 )
 Begin {
  $Report = @()
  Write-Verbose "Get all $($EventID) events from the $($LogName) Log on $($ComputerName)"
  $Events = Get-WinEvent -ComputerName $ComputerName -LogName $LogName -Credential $Credentials | Where-Object { $_.Id -eq $EventID }
  Write-Verbose "Filter the list of events to only events that happened today"
  $Events = $Events | Where-Object { (Get-Date($_.TimeCreated) -Format "yyy-MM-dd") -eq (Get-Date -Format "yyy-MM-dd") }
 }
 Process {
  Write-Verbose "Loop through each event that is returned from Get-WinEvent"
  foreach ($Event in $EventID4625) {
   Write-Verbose "Create an object to hold the data I'm collecting"
   $ThisEvent = New-Object -TypeName PSObject -Property @{
    TimeCreated    = $Event.TimeCreated
    MachineName    = $Event.MachineName
    TargetUserName = $Event.Properties[5].Value
    LogonType      = $Event.Properties[10].Value
    IpAddress      = [net.ipaddress]$Event.Properties[19].Value
    IpPort         = $Event.Properties[20].Value
    Message        = $Event.Message
   }
   $Report += $ThisEvent
  }
 }
 End {
  Return $Report
 }
}