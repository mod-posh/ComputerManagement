Function Get-NonStandardServiceAccount {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-NonStandardServiceAccount.md#get-nonstandardserviceaccount')]
  Param
  (
    [string]$Computer = (& hostname),
    [pscredential]$Credentials,
    [string]$Filter = "localsystem|NT Authority\LocalService|NT Authority\NetworkService"
  )
  Begin {
    $Filter = $Filter.Replace("\", "\\")
  }
  Process {
    If ($Computer -eq (& hostname)) {
      $Services = Get-CimInstance -ClassName Win32_Service | Select-Object __Server, StartName, Name, DisplayName
    }
    Else {
      $Result = Test-Connection -Count 1 -Computer $Computer -ErrorAction SilentlyContinue

      If ($null -ne $result) {
        $Services = Get-CimInstance -ClassName Win32_Service -ComputerName $Computer -Credential $Credentials `
        | Select-Object __Server, StartName, Name, DisplayName
      }
      Else {
        #	Should do something with unreachable computers here.
      }
    }

    $Suspect = $Services | Where-Object { $_.StartName -notmatch $Filter }
  }
  End {
    Return $Suspect
  }
}
Function Get-PendingUpdate {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PendingUpdate.md#get-pendingupdate')]
  Param
  (
    [Parameter(ValueFromPipeline = $True)]
    [string]$ComputerName
  )
  Begin {
  }
  Process {
    ForEach ($Computer in $ComputerName) {
      If (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
        Try {
          $Updates = [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session", $Computer))
          $Searcher = $Updates.CreateUpdateSearcher()
          $searchresult = $Searcher.Search("IsInstalled=0")
        }
        Catch {
          Write-Warning "$($Error[0])"
          Break
        }
      }
    }
  }
  End {
    Return $SearchResult.Updates
  }
}
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