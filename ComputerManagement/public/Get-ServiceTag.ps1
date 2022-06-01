Function Get-ServiceTag {
 [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-ServiceTag.md#get-servicetag')]
 Param
 (
  $ComputerName = (& hostname)
 )
 Begin {
 }
 Process {
  Try {
   $null = Test-Connection -ComputerName $ComputerName -Count 1 -ErrorAction 'Stop'
   if ($ComputerName -eq (& hostname)) {
    $SerialNumber = (Get-CimInstance -ClassName Win32_Bios -ErrorAction 'Stop').SerialNumber
   }
   else {
    $SerialNumber = (Get-CimInstance -ClassName Win32_Bios -ComputerName $ComputerName -Credential $Credentials -ErrorAction 'Stop').SerialNumber
   }
   $Return = New-Object PSObject -Property @{
    ComputerName = $ComputerName
    SerialNumber = $SerialNumber
   }
  }
  Catch {
   $Return = $Error[0].Exception
  }
 }
 End {
  Return $Return
 }
}