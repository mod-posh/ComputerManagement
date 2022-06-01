Function Export-EventLog {
 [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Export-EventLog.md#export-eventlog')]
 Param
 (
  $ComputerName,
  [pscredential]$Credential,
  [switch]$ListLog,
  $LogName,
  $Destination
 )
 Begin {
  $Remote = $false
  if (!($ComputerName)) {
   Write-Verbose "No ComputerName passed, setting ComputerName to $(& hostname)"
   $ComputerName = (& hostname)
  }
  if ($Credential) {
   Write-Verbose "Attempting to connect to $($ComputerName) as $($Credential.Username)"
   $EventSession = New-Object System.Diagnostics.Eventing.Reader.EventLogSession($ComputerName, `
     $Credential.GetNetworkCredential().Domain, `
     $Credential.GetNetworkCredential().Username, `
     $Credential.Password, 'Default')
   $Remote = $true
  }
  else {
   Write-Verbose "Connecting to $($ComputerName)"
   $EventSession = New-Object System.Diagnostics.Eventing.Reader.EventLogSession($ComputerName)
  }
 }
 Process {
  switch ($ListLog) {
   $true {
    try {
     Write-Verbose "Outputting a list of all lognames"
     $EventSession.GetLogNames()
    }
    catch {
     Write-Error $Error[0]
     break
    }
   }
   $false {
    try {
     if ($null -eq ($EventSession.GetLogNames() | Where-Object { $_ -eq $LogName })) {
      Write-Error "There is not an event log on the $($ComputerName) computer that matches `"$($LogName)`""
     }
     else {
      if ($Remote) {
       Write-Verbose "Checking to see if \\$($ComputerName)\$((([System.IO.Directory]::GetParent($Destination)).FullName).Replace(":","$")) exists"
       if ((Test-Path -Path "\\$($ComputerName)\$((([System.IO.Directory]::GetParent($Destination)).FullName).Replace(":","$"))") -ne $true) {
        Write-Verbose "Creating $((([System.IO.Directory]::GetParent($Destination)).FullName).Replace(":","$"))"
        $ScriptBlock = { New-Item -Path $args[0] -ItemType Directory -Force }
        Invoke-Command -ScriptBlock $ScriptBlock -ComputerName $ComputerName -Credential $Credential -ArgumentList (([System.IO.Directory]::GetParent($Destination)).FullName) | Out-Null
       }
      }
      else {
       Write-Verbose "Checking to see if $($Destination) exists."
       if ((Test-Path $Destination) -ne $true) {
        Write-Verbose "Creating $((([System.IO.Directory]::GetParent($Destination)).FullName).Replace(":","$"))"
        New-Item -Path (([System.IO.Directory]::GetParent($Destination)).FullName) -ItemType Directory -Force | Out-Null
       }
      }
      Write-Verbose "Exporting event log $($LogName) to the following location $($Destination)"
      $EventSession.ExportLogAndMessages($LogName, 'LogName', '*', $Destination)
     }
    }
    catch {
     Write-Error $Error[0]
     break
    }
   }
  }

 }
 End {
 }
}