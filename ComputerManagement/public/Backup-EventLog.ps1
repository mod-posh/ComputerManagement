Function Backup-EventLog {
 [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Backup-EventLog.md#backup-eventlog')]
 Param
 (
  [string]$ComputerName,
  [string]$LogPath = "C:\Windows\system32\winevt\Logs",
  [string]$BackupPath = "C:\Logs"
 )
 Begin {
  $EventLogs = "\\$($Computername)\$($LogPath.Replace(":","$"))"
  If ((Test-Path $BackupPath) -ne $True) {
   New-Item $BackupPath -Type Directory | Out-Null
  }
 }
 Process {
  Try {
   Copy-Item $EventLogs -Destination $BackupPath -Recurse
  }
  Catch {
   Return $Error
  }
 }
 End {
  Return $?
 }
}