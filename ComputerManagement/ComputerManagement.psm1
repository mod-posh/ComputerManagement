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