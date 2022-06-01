Function Get-RDPLoginEvent {
 [OutputType([Object[]])]
 [cmdletbinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-RDPLoginEvent.md#Get-rdploginevent')]
 Param
 (
  [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
  $ComputerName,
  [pscredential]$Credentials
 )
 Begin {
  $LoginAttempts = @()
  $EventID = 1149
  $LogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'

 }
 Process {
  Foreach ($Computer in $ComputerName) {
   Write-Verbose "Checking $($Computer)"
   try {
    if (Test-Connection -ComputerName $Computer -Count 1 -ErrorAction SilentlyContinue) {
     $Events = Get-WinEvent -LogName $LogName -ComputerName $ComputerName -Credential $Credentials  -ErrorAction SilentlyContinue `
     | Where-Object { $_.ID -eq $EventID }
     if ($null -ne $Events.Count) {
      foreach ($Event in $Events) {
       $LoginAttempt = New-Object -TypeName PSObject -Property @{
        ComputerName         = $Computer
        User                 = $Event.Properties[0].Value
        Domain               = $Event.Properties[1].Value
        SourceNetworkAddress = [net.ipaddress]$Event.Properties[2].Value
        TimeCreated          = $Event.TimeCreated
       }
       $LoginAttempts += $LoginAttempt
      }
     }
    }
   }
   catch {
    throw $_;
   }
  }
 }
 End {
  Return $LoginAttempts
 }
}