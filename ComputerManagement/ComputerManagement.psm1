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
Function Get-InvalidLogonAttempt {
  [cmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-InvalidLogonAttempt.md#get-invalidlogonattempt')]
  Param
  (
    [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
    $ComputerName,
    $LogName = "Security",
    $EventID = 4625
  )
  Begin {
    $Report = @()
    Write-Verbose "Get all $($EventID) events from the $($LogName) Log on $($ComputerName)"
    $Events = Get-WinEvent -ComputerName $ComputerName -LogName $LogName -Credential $Credentials | Where-Object { $_.Id -eq $EventID }
    Write-Verbose "Filter the list of events to only events that happened today"
    $Events = $Events | Where-Object { (Get-Date($_.TimeCreated) -Format "yyy-MM-dd") -eq (Get-Date -Format "yyy-MM-dd") }
  }
  Process {
    Write-Verbose "Loop through each event that is returned from Get-WinEvent"
    foreach ($Event in $EventID4625) {
      Write-Verbose "Create an object to hold the data I'm collecting"
      $ThisEvent = New-Object -TypeName PSObject -Property @{
        TimeCreated    = $Event.TimeCreated
        MachineName    = $Event.MachineName
        TargetUserName = $Event.Properties[5].Value
        LogonType      = $Event.Properties[10].Value
        IpAddress      = [net.ipaddress]$Event.Properties[19].Value
        IpPort         = $Event.Properties[20].Value
        Message        = $Event.Message
      }
      $Report += $ThisEvent
    }
  }
  End {
    Return $Report
  }
}
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
Function Get-DiskUsage {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-DiskUsage.md#get-diskusage')]
  Param
  (
    [string]$Path = "."
  )
  Begin {
  }
  Process {
    foreach ($Folder in (Get-ChildItem $Path)) {
      $ErrorActionPreference = "SilentlyContinue"
      try {
        $FolderSize = Get-ChildItem -Recurse $Folder.FullName | Measure-Object -Property Length -Sum
        if ($null -eq $FolderSize) {
          Write-Verbose $Error[0].ToString()
          $FolderSize = 0
        }
        else {
          $FolderSize = $FolderSize.sum
        }
      }
      catch {
        throw $_;
      }
      New-Object -TypeName PSobject -Property @{
        FolderName = $Folder.FullName
        FolderSize = $FolderSize
      }
    }
  }
  End {
  }
}
Function New-Password {
  [OutputType([System.Object[]])]
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/New-Password.md#new-password',
    SupportsShouldProcess,
    ConfirmImpact = 'Low')]
  Param
  (
    [int]$Length = 32,
    [int]$Count = 10,
    [switch]$Strong,
    [switch]$asSecureString
  )
  Begin {
    switch ($Strong) {
      $true {
        [string]$Characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 !@#$%^&*()_+{}|[]\:;'<>?,./`~"
      }
      $false {
        [string]$Characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
      }
    }
    $Passwords = @()
  }
  Process {
    if ($PSCmdlet.ShouldProcess("New", "New Password")) {
      for ($Counter = 1; $Counter -le $Count; $Counter++) {
        $bytes = new-object "System.Byte[]" $Length
        $rnd = new-object System.Security.Cryptography.RNGCryptoServiceProvider
        $rnd.GetBytes($bytes)
        $result = ""
        for ( $i = 0; $i -lt $Length; $i++ ) {
          $result += $Characters[ $bytes[$i] % $Characters.Length ]
        }
        if ($asSecureString) {
          $SecurePassword = New-Object securestring;
          foreach ($Char in $result.ToCharArray()) {
            $SecurePassword.AppendChar($Char);
          }
          $Passwords += $SecurePassword;
        }
        else {
          $Password = New-Object -TypeName PSobject -Property @{
            Password = $result
          }
          $Passwords += $Password
        }
      }
    }
  }
  End {
    Return $Passwords
  }
}
function Connect-Rdp {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Connect-Rdp.md#connect-rdp')]
  param
  (
    [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
    $ComputerName,
    [pscredential]$Credential
  )
  Process {
    # take each computername and process it individually
    Foreach ($Computer in $ComputerName) {
      # if the user has submitted a credential, store it
      # safely using cmdkey.exe for the given connection
      if ($PSBoundParameters.ContainsKey('Credential')) {
        # extract username and password from credential
        $User = $Credential.UserName
        $Password = $Credential.GetNetworkCredential().Password

        # save information using cmdkey.exe
        cmdkey.exe /generic:$Computer /user:$User /pass:$Password
      }
      # initiate the RDP connection
      # connection will automatically use cached credentials
      # if there are no cached credentials, you will have to log on
      # manually, so on first use, make sure you use -Credential to submit
      # logon credential
      mstsc.exe /v $Computer /f
    }
  }
}
Function Get-NetShare {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-NetShare.md#get-netshare')]
  Param
  (
    [parameter(Mandatory = $true)]
    [string]$ComputerName,
    [ValidateSet("Print", "Disk", IgnoreCase = $true)]
    [parameter(Mandatory = $true)]
    [string]$Type
  )
  Begin {
    Write-Verbose "Getting share from server"
    $List = net view "\\$($ComputerName)" | Select-String $Type
    Write-Verbose "$($List)"
  }
  Process {
    foreach ($Entry in $List) {
      Write-Verbose "Converting regex to string"
      $Line = $Entry.ToString();
      Write-Debug $Line
      Write-Verbose "Building share property"
      $Share = $Line.Substring(0, $Line.IndexOf($Type)).trim()
      Write-Verbose "Building Description property"
      $Description = $Line.Substring($Line.IndexOf($Type), $Line.Length - $Line.IndexOf($Type)).Replace($Type, "").Trim()
      $Path = "\\$($ComputerName)\$($Share)"
      New-Object -TypeName psobject -Property @{
        Server      = $ComputerName
        Share       = $Share
        Description = $Description
        Path        = $Path
      } | Select-Object -Property Server, Share, Description, Path
    }
  }
  End {
  }
}