Function Set-Pass {
  [OutputType([System.String])]
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Set-Pass.md#set-pass',
    SupportsShouldProcess,
    ConfirmImpact = 'Low')]
  Param
  (
    [Parameter(Mandatory = $true)]
    [string]$ComputerName,
    [Parameter(Mandatory = $true)]
    [string]$UserName,
    [Parameter(Mandatory = $true)]
    [securestring]$Password
  )
  Begin {
  }
  Process {
    Try {
      if ($PSCmdlet.ShouldProcess("Change", "Change password for $($UserName)")) {
        $User = [adsi]("WinNT://$ComputerName/$UserName, user")
        $User.psbase.invoke("SetPassword", ($Password | ConvertFrom-SecureString -AsPlainText))

        Return "Password updated"
      }
    }
    Catch {
      Return $Error[0].Exception.InnerException.Message.ToString().Trim()
    }
  }
  End {
  }
}
Function New-ScheduledTask {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/New-ScheduledTask.md#new-scheduledtask',
    SupportsShouldProcess,
    ConfirmImpact = 'Medium')]
  Param
  (
    [Parameter(Mandatory = $true)]
    [string]$TaskName,
    [Parameter(Mandatory = $true)]
    [string]$TaskRun,
    [Parameter(Mandatory = $true)]
    [string]$TaskSchedule,
    [Parameter(Mandatory = $true)]
    [string]$StartTime,
    [Parameter(Mandatory = $true)]
    [string]$StartDate,
    [Parameter(Mandatory = $true)]
    [string]$TaskUser,
    [Parameter(Mandatory = $true)]
    [string]$Server
  )
  Begin {
  }
  Process {
    if ($PSCmdlet.ShouldProcess("New", "Create new Scheduled Task on $($Server)")) {
      schtasks /create /tn $TaskName /tr $TaskRun /sc $TaskSchedule /st $StartTime /sd $StartDate /ru $TaskUser /s $Server
    }
  }
  End {
    Return $?
  }
}
Function Remove-UserFromLocalGroup {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Remove-UserFromLocalGroup.md#remove-userfromlocalgroup',
    SupportsShouldProcess,
    ConfirmImpact = 'Medium')]
  Param
  (
    [Parameter(Mandatory = $true)]
    [string]$ComputerName,
    [Parameter(Mandatory = $true)]
    [string]$UserName,
    [Parameter(Mandatory = $true)]
    [string]$GroupName
  )
  Begin {
  }
  Process {
    if ($PSCmdlet.ShouldProcess("Remove", "Remove $($Username) from $($GroupName)")) {
      $Computer = [ADSI]("WinNT://$($ComputerName)");
      $User = [adsi]("WinNT://$ComputerName/$UserName, user")
      $Group = $Computer.psbase.children.find($GroupName)
      $Group.Remove("WinNT://$Computer/$User")
    }
  }
  End {
    Return $?
  }
}
Function Get-CimService {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-CimService.md#get-cimservice')]
  Param
  (
    [string]$Computer = (& hostname),
    [pscredential]$Credential,
    [string]$State = "Running",
    [string]$StartMode = "Auto"
  )
  Begin {
  }
  Process {
    If ($Computer -eq (& hostname)) {
      $Services = Get-CimInstance -ClassName Win32_Service -Filter "State = '$State' and StartMode = '$StartMode'"
    }
    Else {
      If ($null -eq $Credential) {
        $Credential = Get-Credential
      }
      $Services = Get-CimInstance -ClassName Win32_Service -Filter "State = '$State' and StartMode = '$StartMode'" `
        -ComputerName $Computer -Credential $Credential
    }
  }
  End {
    Return $Services
  }
}
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
Function Remove-LocalUser {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Remove-LocalUser.md#remove-localuser',
    SupportsShouldProcess,
    ConfirmImpact = 'Medium')]
  Param
  (
    [Parameter(Mandatory = $true)]
    $ComputerName,
    [Parameter(Mandatory = $true)]
    $UserName
  )
  Begin {
    $isAlive = Test-Connection -ComputerName $ComputerName -Count 1 -ErrorAction SilentlyContinue
  }
  Process {
    if ($null -ne $isAlive) {
      if ($PSCmdlet.ShouldProcess("Remove", "Remove $($Username) from $($ComputerName)")) {
        $ADSI = [adsi]"WinNT://$ComputerName"
        $Users = $ADSI.psbase.children | Where-Object { $_.psBase.schemaClassName -eq "User" } | Select-Object -ExpandProperty Name
        foreach ($User in $Users) {
          if ($User -eq $UserName) {
            $ADSI.Delete("user", $UserName)
            $Return = "Deleted"
          }
          else {
            $Return = "User not found"
          }
        }
      }
    }
    else {
      $Return = "$ComputerName not available"
    }
  }
  End {
    Return $Return
  }
}
Function Get-PendingUpdates {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PendingUpdates.md#get-pendingupdates')]
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
Function Backup-EventLogs {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Backup-EventLogs.md#backup-eventlogs')]
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
Function Get-PaperCutLogs {
  [OutputType([Object[]])]
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PaperCutLogs.md#get-papercutlogs')]
  Param
  (
    $PrintServers = @("ps1.company.com", "ps2.company.com")
  )
  Begin {
    # Location of the monthly PaperCut logs
    $PcutLogLocation = "c$\Program Files (x86)\PaperCut Print Logger\logs\csv\monthly"
    # Column headings in the CSV
    $PcutHeader = "Time", "User", "Pages", "Copies", "Printer", "Document Name", "Client", "Paper Size", "Language", "Height", "Width", "Duplex", "Grayscale", "Size"
    # Need it set to stop in order for the try/catch to work
    $ErrorActionPreference = "Stop"
    # Define an empty array to hold all the log entries
    $PcutReport = @()
  }
  Process {
    foreach ($PrintServer in $PrintServers) {
      # Get each log file from the server
      Try {
        $PcutLogs = Get-ChildItem "\\$($PrintServer)\$($PcutLogLocation)"
      }
      Catch {
        # This runs only if we're trying to pull logs from an x86 print server
        $PcutLogs = Get-ChildItem "\\$($PrintServer)\c$\Program Files\PaperCut Print Logger\logs\csv\monthly"
      }

      Foreach ($PcutLog in $PcutLogs) {
        # Import the csv into a variable, skip 1 skips the first line of the PaperCut CSV
        # which has information not related to the log itself
        $ThisReport = Import-Csv $PcutLog.FullName -Header $PcutHeader | Select-Object -Skip 1

        # Add this log to the array
        $PcutReport += $ThisReport | Where-Object { $_.Time -ne "Time" }
      }
    }
  }
  End {
    # Display the result, this can be piped into Export-CSV to generate a large
    # spreadsheet suitable for analysis
    Return $PcutReport
  }
}
Function Set-ShutdownMethod {
  [OutputType([System.String])]
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Set-ShutdownMethod.md#set-shutdownmethod',
    SupportsShouldProcess,
    ConfirmImpact = 'High')]
  PARAM
  (
    [parameter(Mandatory = $True, ValueFromPipeline = $True)]
    [string]$ComputerName,
    [pscredential]$Credentials = (Get-Credential),
    [int32]$ShutdownMethod = 0
  )
  Begin {
  }
  Process {
    Try {
      if ($PSCmdlet.ShouldProcess("Shutdown", "Shutdown $($ComputerName)")) {
        $ReturnValue = (Get-CimInstance -Class Win32_OperatingSystem -ComputerName $ComputerName -Credential $Credentials).InvokeMethod("Win32Shutdown", $ShutdownMethod)
      }
    }
    Catch {
      $ReturnValue = $Error[0]
    }
  }
  End {
    if ($ReturnValue -ne 0) {
      Return "An error occurred, most likely there is nobody logged into $($ComputerName)"
    }
    else {
      Return "Success"
    }
  }
}
Function Get-PrinterLogs {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PrinterLogs.md#get-printerlogs')]
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
Function Get-OpenSessions {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-OpenSessions.md#get-opensessions')]
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
Function Get-OpenFiles {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-OpenFiles.md#get-openfiles')]
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
Function Get-RDPLoginEvents {
  [OutputType([Object[]])]
  [cmdletbinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-RDPLoginEvents.md#Get-rdploginevents')]
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
Function Get-InvalidLogonAttempts {
  [cmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-InvalidLogonAttempts.md#get-invalidlogonattempts')]
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
Function Get-MappedDrives {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-MappedDrives.md#get-mappeddrives')]
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
Function Get-Namespace {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-Namespace.md#get-namespace')]
  Param
  (
    [parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [string]$Namespace,
    [parameter(Mandatory = $true)]
    [string]$ComputerName
  )
  Begin {
    Write-Verbose 'Create an SWbemLocator object to connect to the computer'
    $WbemLocator = New-Object -ComObject "WbemScripting.SWbemLocator"
    Write-Verbose "Make a connection to $($ComputerName) and access $($Namespace)"
    $WbemServices = $WbemLocator.ConnectServer($ComputerName, $Namespace)
    Write-Verbose "Use the SubClassesOf() method of the SWbemServices object to return an SWbemObjectSet"
    $WbemObjectSet = $WbemServices.SubclassesOf()
  }
  Process {
  }
  End {
    Write-Verbose 'Return the Path_ property of the ObjectSet as this seems to contain useful information'
    Return $WbemObjectSet | Select-Object -Property Path_ -ExpandProperty Path_
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
Function Get-WinEventTail {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-WinEventTail.md#get-wineventtail')]
  Param
  (
    [string]$LogName = 'System',
    [int]$ShowExisting = 10
  )
  Begin {
    if ($ShowExisting -gt 0) {
      $Data = Get-WinEvent -LogName $LogName -MaxEvents $ShowExisting
      $Data | Sort-Object -Property RecordId
      $Index1 = $Data[0].RecordId
    }
    else {
      $Index1 = (Get-WinEvent -LogName $LogName -MaxEvents 1).RecordId
    }
  }
  Process {
    while ($true) {
      Start-Sleep -Seconds 1
      $Index2 = (Get-WinEvent -LogName $LogName -MaxEvents 1).RecordId
      if ($Index2 -gt $Index1) {
        Get-WinEvent -LogName $LogName -MaxEvents ($Index2 - $Index1) | Sort-Object -Property RecordId
      }
      $Index1 = $Index2
    }
  }
  End {
  }
}
function Open-CdDrive {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Open-CdDrive.md#open-cddrive')]
  param
  (
    [string]$Drive
  )
  Begin {
    $sApplication = new-object -com Shell.Application
    $MyComputer = 17
  }
  Process {
    if ($Drive) {
      $Cdrom = $sApplication.Namespace(17).ParseName($Drive)
      $Cdrom.InvokeVerb("Eject")
      $Cdrom
    }
    else {
      $Cdrom = $sApplication.NameSpace($MyComputer).Items() | Where-Object -Property Type -eq 'CD Drive'
      foreach ($Cd in $Cdrom) {
        $Cd.InvokeVerb('Eject')
        $cd
      }
    }
  }
  end {
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($sApplication) | Out-Null
    Remove-Variable sApplication
  }
}
Function Grant-RegistryPermission {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Grant-RegistryPermission.md#grant-registrypermission')]
  Param
  (
    [Parameter(Mandatory = $true)]
    [string] $Path,
    [Parameter(Mandatory = $true)]
    [string] $Principal,
    [Parameter(Mandatory = $true)]
    [Security.AccessControl.RegistryRights] $Rights,
    [Security.AccessControl.InheritanceFlags] $Inheritance = [Security.AccessControl.InheritanceFlags]::None,
    [Security.AccessControl.PropagationFlags] $Propagation = [Security.AccessControl.PropagationFlags]::None
  )
  Begin {
    $Identity = new-object System.Security.Principal.NTAccount($Principal)
    $IdentityReference = $Identity.Translate([System.Security.Principal.SecurityIdentifier])
  }
  Process {
    $RegistryAccessRule = New-Object Security.AccessControl.RegistryAccessRule $IdentityReference, $Rights, $Inheritance, $Propagation, Allow
    $Acl = Get-Acl $Path
    $Acl.AddAccessRule($RegistryAccessRule)
    Set-Acl -Path $Path -AclObject $Acl
  }
  End {
    Get-Acl $Path
  }
}
function New-Credential {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/New-Credential.md#new-credential',
    SupportsShouldProcess,
    ConfirmImpact = 'Low')]
  Param
  (
    [Parameter(Mandatory = $true)]
    [string]$Username,
    [Parameter(Mandatory = $true)]
    [securestring]$Password
  )
  begin {

  }
  process {
    if ($PSCmdlet.ShouldProcess("New", "New Credential")) {
      New-Object System.Management.Automation.PSCredential ($Username, $Password)
    }
  }
  end {

  }
}