Function Get-MappedDrive {
 [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-MappedDrive.md#get-mappeddrive')]
 Param
 (
  [string]$ComputerName = (hostname),
  [System.Management.Automation.PSCredential]$Credentials
 )
 Begin {
  $LocalHost = $true
  if ($ComputerName.ToLower().IndexOfAny((& hostname)) -gt 0) {
   Write-Verbose "$($ComputerName) is not $((& hostname).ToLower())"
   $LocalHost = $false
  }
 }
 Process {
  switch ($LocalHost) {
   $true {
    try {
     Write-Verbose "Connecting the Win32_MappedLogicalDisk of the local computer"
     $DriveMaps = Get-CimInstance -Class Win32_MappedLogicalDisk
    }
    catch {
     return $Error[0]
    }
   }
   $false {
    try {
     Write-Verbose "Connecting the Win32_MappedLogicalDisk of $($ComputerName.ToLower())"
     $DriveMaps = Get-CimInstance -Class Win32_MappedLogicalDisk -ComputerName $ComputerName -Credential $Credentials
    }
    catch {
     return $Error[0]
    }
   }
  }
 }
 End {
  Write-Verbose "Returning the most common properties"
  Return $DriveMaps | Select-Object -Property Caption, FreeSpace, Name, ProviderName, Size, VolumeName
 }
}