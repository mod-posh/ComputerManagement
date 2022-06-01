Function Get-PrinterLog {
 [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PrinterLog.md#get-printerlog')]
 Param
 (
  $LogName = "Microsoft-Windows-PrintService/Operational",
  [Parameter(Mandatory = $true)]
  $ComputerName
 )
 Begin {
  $ErrorActionPreference = "Stop"
  $PrintJobs = Get-WinEvent -ComputerName $ComputerName -LogName $LogName -Credential $Credentials | Where-Object { $_.Id -eq 307 }
  $PrintLogs = @()
 }
 Process {
  foreach ($PrintJob in $PrintJobs) {
   $Client = $PrintJob.Properties[3].Value
   if ($Client.IndexOf("\\") -gt -1) {
    $Client = $Client.Substring(2, ($Client.Length) - 2)
   }

   Try {
    [string]$Return = Resolve-DnsName -Name $Client | Where-Object -Property Name -like "*$($Client)*"
    $Client = $Return.Substring($Return.IndexOf(" "), (($Return.Length) - $Return.IndexOf(" "))).Trim()
   }
   Catch {
    $Client = $PrintJob.Properties[3].Value
   }
   $PrintLog = New-Object -TypeName PSObject -Property @{
    Time     = $PrintJob.TimeCreated
    Job      = $PrintJob.Properties[0].Value
    Document = $PrintJob.Properties[1].Value
    User     = $PrintJob.Properties[2].Value
    Client   = $Client
    Printer  = $PrintJob.Properties[4].Value
    Port     = $PrintJob.Properties[5].Value
    Size     = $PrintJob.Properties[6].Value
    Pages    = $PrintJob.Properties[7].Value
   }
   $PrintLogs += $PrintLog
  }
 }
 End {
  Return $PrintLogs
 }
}