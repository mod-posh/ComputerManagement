Function New-LocalUser {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/New-LocalUser#new-localuser',
    SupportsShouldProcess,
    ConfirmImpact = 'Low')]
  Param
  (
    [Parameter(Mandatory = $true)]
    [string]$ComputerName,
    [Parameter(Mandatory = $true)]
    [string]$User,
    [Parameter(Mandatory = $true)]
    [securestring]$Password,
    [string]$Description
  )
  Begin {
  }
  Process {
    Try {
      if ($PSCmdlet.ShouldProcess("Create", "Create new user on $($Computername)")) {
        $objComputer = [ADSI]("WinNT://$($ComputerName)")
        $objUser = $objComputer.Create("User", $User)
        $objUser.SetPassword(($password | ConvertFrom-SecureString -AsPlainText))
        $objUser.SetInfo()
        $objUser.description = $Description
        $objUser.SetInfo()
        Return $?
      }
    }
    Catch {
      Return $Error[0].Exception.InnerException.Message.ToString().Trim()
    }
  }
  End {
  }
}
Function Set-Pass {
  [OutputType([System.String])]
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Set-Pass#set-pass',
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
Function Add-LocalUserToGroup {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Add-LocalUserToGroup#add-localusertogroup')]
  Param
  (
    [Parameter(Mandatory = $true)]
    [string]$ComputerName,
    [Parameter(Mandatory = $true)]
    [string]$User,
    [Parameter(Mandatory = $true)]
    [string]$Group
  )
  Begin {
  }
  Process {
    Try {
      $objComputer = [ADSI]("WinNT://$($ComputerName)/$($Group),group")
      $objComputer.add("WinNT://$($ComputerName)/$($User),group")
      Return $?
    }
    Catch {
      Return $Error[0].Exception.InnerException.Message.ToString().Trim()
    }
  }
  End {
  }
}
Function New-ScheduledTask {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/New-ScheduledTask#new-scheduledtask',
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
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Remove-UserFromLocalGroup#remove-userfromlocalgroup',
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
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-CimService#get-cimservice')]
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
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-NonStandardServiceAccount#get-nonstandardserviceaccount')]
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
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Remove-LocalUser#remove-localuser',
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
Function Get-LocalUserAccounts {
  [OutputType([Object])]
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-LocalUserAccounts#get-localuseraccounts')]
  Param
  (
    [string]$ComputerName = (& hostname),
    [System.Management.Automation.PSCredential]$Credentials
  )
  Begin {
    $Filter = "LocalAccount=True"
    $isAlive = Test-Connection -ComputerName $ComputerName -Count 1 -ErrorAction SilentlyContinue
  }
  Process {
    if ($null -ne $isAlive) {
      $ScriptBlock += " -ComputerName $ComputerName"
      if ($Credentials) {
        if ($isAlive.__SERVER.ToString() -eq $ComputerName) {
        }
        else {
          Return (Get-CimInstance -ClassName Win32_UserAccount -Filter $Filter -Credential $Credentials | Select-Object -Property Name, SID)
        }
      }
    }
    else {
      throw "Unable to connect to $ComputerName"
    }
  }
  End {
    Return (Get-CimInstance -ClassName Win32_UserAccount -Filter $Filter | Select-Object Name, SID)
  }
}
Function Get-PendingUpdates {
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PendingUpdates#get-pendingupdates')]
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
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-ServiceTag#get-servicetag')]
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
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Backup-EventLogs#backup-eventlogs')]
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
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Export-EventLog#export-eventlog')]
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
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PaperCutLogs#get-papercutlogs')]
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
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Set-ShutdownMethod#set-shutdownmethod',
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
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PrinterLogs#get-printerlogs')]
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
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-OpenSessions#get-opensessions')]
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
  [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-OpenFiles#get-openfiles')]
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
  <#
  .SYNOPSIS
  Return Remote Desktop login attempts
  .DESCRIPTION
  This function returns login attempts from the Microsoft Windows TerminalServices RemoteConnectionManager
  log. The specific events are logged as EventID 1149, and they are logged whether or not the user actually
  gets to the desktop.
  .PARAMETER ComputerName
  This is the NetBIOS name of the computer to pull events from.
  .PARAMETER Credentials
  A user account with the ability to retreive these events.
  .EXAMPLE
  Get-RDPLoginEvents -Credentials $Credentials |Export-Csv -Path C:\logfiles\RDP-Attempts.csv

  Description
  -----------
  This example show piping the output of the function to Export-Csv to create a file suitable for import
  into Excel, or some other spreadsheet software.
  .EXAMPLE
  Get-RDPLoginEvents -Credentials $Credentials -ComputerName MyPC |Format-Table

  SourceNetworkAddress        Domain           TimeCreated                User
  --------------------        ------           -----------                ----
  192.168.1.1                 MyPC...          4/30/2011 8:20:02 AM       Administrator...
  192.168.1.1                 MyPC...          4/28/2011 4:53:01 PM       Administrator...
  192.168.1.1                 MyPC...          4/21/2011 2:01:42 PM       Administrator...
  192.168.1.1                 MyPC...          4/19/2011 11:42:59 AM      Administrator...
  192.168.1.1                 MyPC...          4/19/2011 10:30:52 AM      Administrator...

  Description
  -----------
  This example shows piping the output to Format-Table
  .NOTES
  The Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational needs to be enabled
  The user account supplied in $Credentials needs to have permission to view this log
  No output is returned if the log is empty.
  .LINK
  https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Get-RDPLoginEvents
  #>
  [cmdletbinding()]
  Param
  (
    [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
    $ComputerName,
    [pscredential]$Credentials,
    $EventID,
    $LogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
  )
  Begin {
    $LoginAttempts = @()
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
  <#
  .SYNOPSIS
  Return a list of invalid logon attempts.
  .DESCRIPTION
  This function queries the security log of a given computer and
  retrieves Event ID 4625, failed logon attempt.
  .PARAMETER ComputerName
  The name of the computer to pull logs from
  .PARAMETER LogName
  The name of the Event Log.

  You will notice that I have set the LogName to Security, since
  this particular script was designed to find a specific entry.
  This can be modified to suit your needs.
  .PARAMETER EventID
  The Event ID to return.

  You will notice that I have set the EventID to 4625, since
  this particular script was designed to find those particular
  entries. This can be modified to suit your needs.
  .EXAMPLE
  Get-InvalidLogonAttempts -ComputerName Desktop-pc1 -LogName 'Security' -EventID 4625

  Message        MachineName    TimeCreated   IpAddress         LogonType TargetUserNam IpPort
  e
  -------        -----------    -----------   ---------         --------- ------------- ------
  An account ... Desktop-pc1... 10/26/2011... ##.###.###...            10 Daniel        62581
  An account ... Desktop-pc1... 10/26/2011... ##.###.###...            10 Daniel        11369
  An account ... Desktop-pc1... 10/26/2011... ##.###.###...            10 Daniel        47575
  An account ... Desktop-pc1... 10/26/2011... ##.###.###...            10 Daniel        51144

  Description
  -----------
  This is the basic syntax of the command, the output is returned to stdin.
  .EXAMPLE
  Get-InvalidLogonAttempts |Export-Csv -Path .\InvalidLoginAttempts.csv

  Description
  -----------
  This example shows redirecting the output through the Export-CSV command to get
  a csv file.
  .NOTES
  ScriptName : Get-InvalidLogonAttempts
  Created By : jspatton
  Date Coded : 10/26/2011 11:20:58
  ScriptName is used to register events for this script
  LogName is used to determine which classic log to write to

  ErrorCodes
  100 = Success
  101 = Error
  102 = Warning
  104 = Information

  If you adjust theh script to look for event id's other than 4625, you will
  want to examine the Event Properties. This is similar to viewing the
  "Friendly" view of an event in the event log. Below are all the properties
  for Event ID 4625.

  00  SubjectUserSid S-1-5-18
  01  SubjectUserName NODE1$
  02  SubjectDomainName SOECS
  03  SubjectLogonId 0x3e7
  04  TargetUserSid S-1-0-0
  05  TargetUserName Daniel
  06  TargetDomainName NODE1
  07  Status 0xc000006d
  08  FailureReason %%2313
  09  SubStatus 0xc0000064
  10  LogonType 10
  11  LogonProcessName User32
  12  AuthenticationPackageName Negotiate
  13  WorkstationName NODE1
  14  TransmittedServices -
  15  LmPackageName -
  16  KeyLength 0
  17  ProcessId 0x3278
  18  ProcessName C:\Windows\System32\winlogon.exe
  19  IpAddress ##.###.###.###
  20  IpPort 51144
  .LINK
  https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Get-InvalidLogonAttempts
  #>
  [cmdletBinding()]
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
  <#
  .SYNOPSIS
  Return a list of mapped network drives on the computer
  .DESCRIPTION
  This function returns a list of mapped network drives from the
  local or remote computer.
  .PARAMETER ComputerName
  The name of the computer to get the list from.
  .PARAMETER Credentials
  A credentials object to pass if needed.
  .EXAMPLE
  Get-MappedDrives

  Caption      : V:
  FreeSpace    : 4129467170816
  Name         : V:
  ProviderName : \\users2.company.com\homedir4\jspatton
  Size         : 10737418240
  VolumeName   : 236

  Description
  -----------
  This is the basic syntax of the command.
  .EXAMPLE
  Get-MappedDrives -ComputerName Desktop-PC01

  Caption      : U:
  FreeSpace    : 134377222144
  Name         : U:
  ProviderName : \\people.company.com\i\jspatton
  Size         : 687194767360
  VolumeName   : IGroup

  Description
  -----------
  This syntax shows passing the optional ComputerName parameter. If this is
  not the local computer and you didn't pass the Credentials object, you
  will be prompted.
  .NOTES
  FunctionName : Get-MappedDrives
  Created by   : jspatton
  Date Coded   : 03/20/2012 16:03:52
  .LINK
  https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Get-MappedDrives
  #>
  [CmdletBinding()]
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
  <#
  .SYNOPSIS
  Get the disk usage of a given path
  .DESCRIPTION
  This function returns the disk usage of a given path
  .PARAMETER Path
  The path to check
  .EXAMPLE
  Get-DiskUsage -Dir c:\

  FolderName              FolderSize
  ----------              ----------
  C:\dcam                        204
  C:\DPMLogs                 1166251
  C:\inetpub                       0
  C:\PerfLogs                      0
  C:\Program Files         504195070
  C:\Program Files (x86)  2747425666
  C:\repository             10294506
  C:\SCRATCH                       0
  C:\scripts                 2218148
  C:\TEMP                          0
  C:\Trail                         0
  C:\Users               16198918163
  C:\Windows             18163280116

  Description
  -----------
  This shows the basic syntax of the command
  .EXAMPLE
  Get-DiskUsage -Dir c:\ |Sort-Object -Property FolderSize

  FolderName              FolderSize
  ----------              ----------
  C:\SCRATCH                       0
  C:\Trail                         0
  C:\TEMP                          0
  C:\PerfLogs                      0
  C:\inetpub                       0
  C:\dcam                        204
  C:\DPMLogs                 1166251
  C:\scripts                 2218148
  C:\repository             10294506
  C:\Program Files         504195070
  C:\Program Files (x86)  2747425666
  C:\Users               16198918163
  C:\Windows             18163345365

  Description
  -----------
  This example shows piping the output through Sort-Object

  .NOTES
  FunctionName : Get-DiskUsage
  Created by   : jspatton
  Date Coded   : 03/21/2012 10:29:24

  If you don't have access to read the contents of a given folder
  the function returns 0.
  .LINK
  https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Get-DiskUsage
  #>
  [CmdletBinding()]
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
  <#
  .SYNOPSIS
  Return a collection of classes from a namespace
  .DESCRIPTION
  This function will return a collection of classes from the provided namespace.
  This method uses SWbemLocator to connect to a computer, the resulting
  SWbemServices object is used to return the SubclassesOf() the given namespace.
  .PARAMETER NameSpace
  The WMI namespace to enumerate
  .PARAMETER ComputerName
  The computer to connect to
  .EXAMPLE
  Get-Namespace -Namespace 'root\ccm' -ComputerName 'sccm'

  Path            : \\SCCM\ROOT\ccm:__NAMESPACE
  RelPath         : __NAMESPACE
  Server          : SCCM
  Namespace       : ROOT\ccm
  ParentNamespace : ROOT
  DisplayName     : WINMGMTS:{authenticationLevel=pkt,impersonationLevel=impersonate}!\\SCCM\ROOT\ccm:__NAMESPACE
  Class           : __NAMESPACE
  IsClass         : True
  IsSingleton     : False
  Keys            : System.__ComObject
  Security_       : System.__ComObject
  Locale          :
  Authority       :

  Description
  -----------
  A simple example showing usage and output of the command.
  .EXAMPLE
  Get-Namespace -Namespace $NameSpace -ComputerName $ComputerName |Select-Object -Property Class

  Class
  -----
  __SystemClass
  __thisNAMESPACE
  __NAMESPACE
  __Provider
  __Win32Provider
  __ProviderRegistration
  __EventProviderRegistration
  __EventConsumerProviderRegistration

  Description
  -----------
  This example shows piping the output of the Get-Namespace function to Select-Object to return
  one of the properties of a class.
  .NOTES
  FunctionName : Get-Namespace
  Created by   : jspatton
  Date Coded   : 05/21/2012 12:50:50
  .LINK
  https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Get-Namespace
  #>
  [CmdletBinding()]
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
  <#
  .SYNOPSIS
  Create a new password
  .DESCRIPTION
  This function creates a password using the cryptographic Random Number Generator see the
  MSDN link for more details.
  .PARAMETER Length
  An integer that defines how long the password should be
  .PARAMETER Count
  An integer that defines how many passwords to create
  .PARAMETER Strong
  A switch that if present will include special characters
  .EXAMPLE
  New-Password -Length 64 -Count 5 -Strong

  Password
  --------
  UkQfV)RHwcQ3a)s8Z#QwSCLxlI*y28kEPmcQUVM2HrACf@PxRJDLk4ffge#1m_8j
  XfAwZOh_lrzLE8NwkSTPs5#LNkW4uZ0Wm_ST5UzERqhY45)HBpN$_@@MxDeLiosW
  h(BN(y^Gip&pU$KJpAAajgopQyoSbCn41m53mc__wV@q$DY5a$iN&O0fnf9hvO1&
  tXkFwY_pe(VIFf$R2^bKyKy)D_H6q^Nz7MgSDylXrV2GIkyiFVnvfbd9KENFuHQz
  &6LPlWRB$#yqD@!IEuJ9JcMTKrsA_t(AbWRGTLx@2Fw__j08n(TGi6wgPE6XlLWg

  Description
  ===========
  This example creates 5 strong passwords that are 64 characters long
  .NOTES
  FunctionName : New-Password
  Created by   : jspatton
  Date Coded   : 05/01/2013 12:20:00

  The main portion of this code was lifted from Peter Provost's site, I modified it
  to handle varying length, and count.
  .LINK
  https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#New-Password
  .LINK
  http://www.peterprovost.org/blog/2007/06/22/Quick-n-Dirty-PowerShell-Password-Generator/
  .LINK
  http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider.aspx
  #>
  [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
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
  <#
  .SYNOPSIS
  Connect to one or more computers over RDP
  .DESCRIPTION
  To securely cache login credentials, you can use the command line utility
  cmdkey.exe. With this utility, you can save a username and a password for
  a given remote connection. Windows will then securely cache the information
  and automatically use it when needed.
  .PARAMETER ComputerName
  The hostname or IP address of the computer to connect to
  .PARAMETER Credential
  A credential object that contains a valid username and password for
  the remote computer
  .EXAMPLE
  Connect-Rdp -ComputerName Server-01 -Credential Company.com\Administrator

  Description
  -----------
  The basic syntax showing a connection to a single machine
  .EXAMPLE
  Connect-Rdp -ComputerName Server-01, 192.168.1.2, server-03.company.com -Credential COMPANY\Administrator

  Description
  -----------
  This example shows connecting to multiple servers at once.
  .EXAMPLE
  "server-04","server-06" |Connect-Rdp -Credential $Credentials

  Description
  -----------
  This example shows passing the computernames over the pipe
  .NOTES
  FunctionName : Connect-RDP
  Created by   : jspatton
  Date Coded   : 06/23/2014 08:48:25
  .LINK
  https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Connect-RDP
  .LINK
  http://www.powershellmagazine.com/2014/04/18/automatic-remote-desktop-connection/
  #>
  [CmdletBinding()]
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
  <#
  .SYNOPSIS
  Return a list of shares without using WMI
  .DESCRIPTION
  This function returns a list of shares using the old net view command. This
  works well in situations where a fierwall may be blocking access.
  .PARAMETER ComputerName
  The name of the server that has file or print shares
  .PARAMETER Type
  This will be either Print or Disk
  Print returns printer shares
  Disk returns file shares
  .EXAMPLE
  Get-NetShare -ComputerName server-01 -Type Print

  Server      Share   Path
  ------      -----   ----
  server-01   hp01    \\server-01\hp01
  server-01   hp02    \\server-01\hp02
  server-01   hp03    \\server-01\hp03

  Description
  -----------
  This example shows the basic usage for this function
  .NOTES
  FunctionName : Get-NetShares
  Created by   : jspatton
  Date Coded   : 10/08/2014 11:08:30
  .LINK
  https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Get-NetShares
  #>
  [CmdletBinding()]
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
  <#
  .SYNOPSIS
  A tail cmdlet for Eventlogs
  .DESCRIPTION
  This function will allow you to tail Windows Event Logs. You specify
  a Logname for either the original logs, Application, System and Security or
  the new format for the newer logs Microsoft-Windows-PowerShell/Operational
  .PARAMETER LogName
  Specify a valid Windows Eventlog name
  .PARAMETER ShowExisting
  An integer to show the number of events to start with, the default is 10
  .EXAMPLE
  Get-WinEventTail -LogName Application


  ProviderName: ESENT

  TimeCreated                     Id LevelDisplayName Message
  -----------                     -- ---------------- -------
  10/9/2014 11:55:51 AM          102 Information      svchost (7528) Instance: ...
  10/9/2014 11:55:51 AM          105 Information      svchost (7528) Instance: ...
  10/9/2014 11:55:51 AM          326 Information      svchost (7528) Instance: ...
  10/9/2014 12:05:49 PM          327 Information      svchost (7528) Instance: ...
  10/9/2014 12:05:49 PM          103 Information      svchost (7528) Instance: ...

  .NOTES
  FunctionName : Get-WinEventTail
  Created by   : jspatton
  Date Coded   : 10/09/2014 13:20:22
  .LINK
  https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Get-WinEventTail
  .LINK
  http://stackoverflow.com/questions/15262196/powershell-tail-windows-event-log-is-it-possible
  #>
  [CmdletBinding()]
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
  <#
  .SYNOPSIS
  A function to eject the CD Drive
  .DESCRIPTION
  This function uses the shell.application comObject to
  eject one or more CD rom drives. I had the need to eject several CDroms
  from servers and wanted an easier way to do it. I found a sample
  in the Technet gallery (see link) and modified to suite my
  needs.
  .PARAMETER Drive
  If present it will eject the drive corresponding to the drive letter
  .EXAMPLE
  Open-CdDrive


  Application  : System.__ComObject
  Parent       : System.__ComObject
  Name         : DVD RW Drive (E:)
  Path         : E:\
  GetLink      :
  GetFolder    : System.__ComObject
  IsLink       : False
  IsFolder     : True
  IsFileSystem : True
  IsBrowsable  : False
  ModifyDate   : 12/30/1899 12:00:00 AM
  Size         : 0
  Type         : CD Drive

  Description
  -----------
  This example shows how to eject any cdrom on the system
  .EXAMPLE
  Open-CdDrive -Drive E:


  Application  : System.__ComObject
  Parent       : System.__ComObject
  Name         : DVD RW Drive (E:)
  Path         : E:\
  GetLink      :
  GetFolder    : System.__ComObject
  IsLink       : False
  IsFolder     : True
  IsFileSystem : True
  IsBrowsable  : False
  ModifyDate   : 12/30/1899 12:00:00 AM
  Size         : 0
  Type         : CD Drive

  Description
  -----------
  This example shows how to eject the CD labled E: from the system
  .NOTES
  FunctionName : Open-CdDrive
  Created by   : Jeffrey
  Date Coded   : 01/10/2015 08:33:30
  .LINK
  https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Open-CdDrive
  .LINK
  https://gallery.technet.microsoft.com/scriptcenter/7d81af29-1cae-4dbb-8027-cd96a985f311
  #>
  [CmdletBinding()]
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
  <#
  .SYNOPSIS
  Grant permissions on registry paths
  .DESCRIPTION
  This function allows you to set permissions on registry paths on a computer. Using
  the parameters you can specify the rights, inheritance and propagation of the rights.
  .PARAMETER Path
  A registry path
  .PARAMETER Principal
  Username in DOMAIN\User format
  .PARAMETER Rights
  Specifies the access control rights that can be applied to registry objects. See
  http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights(v=vs.110).aspx
  .PARAMETER Inheritance
  Inheritance flags specify the semantics of inheritance for access control entries (ACEs). See
  http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.inheritanceflags(v=vs.110).aspx
  .PARAMETER Propagation
  Specifies how Access Control Entries (ACEs) are propagated to child objects. These flags are significant
  only if inheritance flags are present. See
  http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.propagationflags(v=vs.110).aspx
  .EXAMPLE
  Grant-RegistryPermission -Path HKCU:\Environment\ -Principal DOMAIN\User01 -Rights FullControl

  Path                                    Owner               Access
  ----                                    -----               ------
  Microsoft.PowerShell.Core\Registry::... NT AUTHORITY\SYSTEM NT AUTHORITY\RESTRICTED Allow  ReadK...

  Description
  -----------
  This example grants full control to the environment key for user01
  .NOTES
  FunctionName : Grant-RegistryPermission
  Created by   : jspatton
  Date Coded   : 01/12/2015 14:53:41

  I lifted this almost completely from iheartpowershell's blog, this appears to be the first
  iteration of this function, I have since found it copied verbatim onto other blogs, so I feel
  the need to give credit where credit is due.

  I modified this function to build the identity from a username, and pass in the identityrefernce
  object to the rule.
  .LINK
  https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Grant-RegistryPermission
  .LINK
  http://www.iheartpowershell.com/2011/09/grant-registry-permissions.html
  .LINK
  http://msdn.microsoft.com/en-us/library/ms147899(v=vs.110).aspx
  .LINK
  http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights(v=vs.110).aspx
  .LINK
  http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.inheritanceflags(v=vs.110).aspx
  .LINK
  http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.propagationflags(v=vs.110).aspx
  #>
  [CmdletBinding()]
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
  [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
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
Export-ModuleMember *