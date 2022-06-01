Function Get-OpenFile {
 [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-OpenFile.md#get-openfile')]
 Param
 (
  $ComputerName = (hostname)
 )
 Begin {
  $OpenFiles = @()
  $Server = [adsi]"WinNT://$($ComputerName)/LanmanServer"
  $Resources = $Server.PSBase.Invoke("Resources")
 }
 Process {
  foreach ($Resource in $Resources) {
   Try {
    $UserResource = New-Object -TypeName PSobject -Property @{
     User      = $Resource.GetType().InvokeMember("User", "GetProperty", $null, $Resource, $null)
     Path      = $Resource.GetType().InvokeMember("Path", "GetProperty", $null, $Resource, $null)
     LockCount = $Resource.GetType().InvokeMember("LockCount", "GetProperty", $null, $Resource, $null)
    }
   }
   Catch {
    throw $_;
   }
   $OpenFiles += $UserResource
  }
 }
 End {
  Return $OpenFiles
 }
}
