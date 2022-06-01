Function Get-OpenSession {
 [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-OpenSession.md#get-opensession')]
 Param
 (
  $ComputerName = (hostname)
 )
 Begin {
  $ServerSessions = @()
  $Server = [adsi]"WinNT://$($ComputerName)/LanmanServer"
  $Sessions = $Server.PSBase.Invoke("Sessions")
 }
 Process {
  foreach ($Session in $Sessions) {
   Try {
    $UserSession = New-Object -TypeName PSobject -Property @{
     User        = $Session.GetType().InvokeMember("User", "GetProperty", $null, $Session, $null)
     Computer    = $Session.GetType().InvokeMember("Computer", "GetProperty", $null, $Session, $null)
     ConnectTime = $Session.GetType().InvokeMember("ConnectTime", "GetProperty", $null, $Session, $null)
     IdleTime    = $Session.GetType().InvokeMember("IdleTime", "GetProperty", $null, $Session, $null)
    }
   }
   Catch {
    throw $_;
   }
   $ServerSessions += $UserSession
  }
 }
 End {
  Return $ServerSessions
 }
}