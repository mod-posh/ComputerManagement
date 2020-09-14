[![GitHub issues](https://img.shields.io/github/issues/mod-posh/ComputerManagement)](https://github.com/mod-posh/ComputerManagement/issues)
[![GitHub forks](https://img.shields.io/github/forks/mod-posh/ComputerManagement)](https://github.com/mod-posh/ComputerManagement/network)
[![GitHub license](https://img.shields.io/github/license/mod-posh/ComputerManagement)](https://github.com/mod-posh/ComputerManagement/blob/master/LICENSE)
## [Open-CdDrive](docs/Open-CdDrive.md)
```

NAME
    Open-CdDrive
    
SYNOPSIS
    A function to eject the CD Drive
    
    
SYNTAX
    Open-CdDrive [[-Drive] <System.String>] [<CommonParameters>]
    
    
DESCRIPTION
    This function uses the shell.application comObject to eject one or more CD rom drives. I had the need to eject several CDroms from servers and wanted an easier way to do it. I found a sample in the Technet gallery (see link) and 
    modified to suite my needs.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Open-CdDrive.md#open-cddrive
    Technet Gallery https://gallery.technet.microsoft.com/scriptcenter/7d81af29-1cae-4dbb-8027-cd96a985f311

REMARKS
    To see the examples, type: "get-help Open-CdDrive -examples".
    For more information, type: "get-help Open-CdDrive -detailed".
    For technical information, type: "get-help Open-CdDrive -full".
    For online help, type: "get-help Open-CdDrive -online"
```
## [Get-CimService](docs/Get-CimService.md)
```
NAME
    Get-CimService
    
SYNOPSIS
    Get a list of services
    
    
SYNTAX
    Get-CimService [[-Computer] <System.String>] [[-Credential] <System.Management.Automation.PSCredential>] [[-State] <System.String>] [[-StartMode] <System.String>] [<CommonParameters>]
    
    
DESCRIPTION
    This function returns a list of services on a given computer. This list can be filtered based on the given StartMode  (ie. Running, Stopped) as well as filtered on StartMode (ie. Auto, Manual).
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/get-cimservice.md#get-cimservice

REMARKS
    To see the examples, type: "get-help Get-CimService -examples".
    For more information, type: "get-help Get-CimService -detailed".
    For technical information, type: "get-help Get-CimService -full".
    For online help, type: "get-help Get-CimService -online"
```
## [New-Credential](docs/New-Credential.md)
```
NAME
    New-Credential
    
SYNOPSIS
    Create a Credential Object
    
    
SYNTAX
    New-Credential [-Username] <System.String> [-Password] <System.Security.SecureString> [-Confirm] [-WhatIf] [<CommonParameters>]
    
    
DESCRIPTION
    This function creates a new Credential Object for use in Scripts or cmdlets.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/New-Credential.md#new-credential

REMARKS
    To see the examples, type: "get-help New-Credential -examples".
    For more information, type: "get-help New-Credential -detailed".
    For technical information, type: "get-help New-Credential -full".
    For online help, type: "get-help New-Credential -online"
```
## [Get-DiskUsage](docs/Get-DiskUsage.md)
```
NAME
    Get-DiskUsage
    
SYNOPSIS
    Get the disk usage of a given path
    
    
SYNTAX
    Get-DiskUsage [[-Path] <System.String>] [<CommonParameters>]
    
    
DESCRIPTION
    This function returns the disk usage of a given path
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-DiskUsage.md#get-diskusage

REMARKS
    To see the examples, type: "get-help Get-DiskUsage -examples".
    For more information, type: "get-help Get-DiskUsage -detailed".
    For technical information, type: "get-help Get-DiskUsage -full".
    For online help, type: "get-help Get-DiskUsage -online"
```
## [Export-EventLog](docs/Export-EventLog.md)
```
NAME
    Export-EventLog
    
SYNOPSIS
    Export an Eventlog from a local or remote computer
    
    
SYNTAX
    Export-EventLog [[-ComputerName] <System.Object>] [[-Credential] <System.Management.Automation.PSCredential>] [[-LogName] <System.Object>] [[-Destination] <System.Object>] [-ListLog] [<CommonParameters>]
    
    
DESCRIPTION
    This function will export the logname you specify to the folder and filename that you provide. The exported file is in the native format for Event logs.
    
    This function leverages the System.Diagnostics.Eventing.Reader class to export the log of the local or remote computer.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Export-EventLog.md#export-eventlog

REMARKS
    To see the examples, type: "get-help Export-EventLog -examples".
    For more information, type: "get-help Export-EventLog -detailed".
    For technical information, type: "get-help Export-EventLog -full".
    For online help, type: "get-help Export-EventLog -online"
```
## [Backup-EventLogs](docs/Backup-EventLogs.md)
```
NAME
    Backup-EventLogs
    
SYNOPSIS
    Backup Eventlogs from remote computer
    
    
SYNTAX
    Backup-EventLogs [[-ComputerName] <System.String>] [[-LogPath] <System.String>] [[-BackupPath] <System.String>] [<CommonParameters>]
    
    
DESCRIPTION
    This function copies event log files from a remote computer to a backup location.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Backup-EventLogs.md#backup-eventlogs

REMARKS
    To see the examples, type: "get-help Backup-EventLogs -examples".
    For more information, type: "get-help Backup-EventLogs -detailed".
    For technical information, type: "get-help Backup-EventLogs -full".
    For online help, type: "get-help Backup-EventLogs -online"
```
## [Get-InvalidLogonAttempts](docs/Get-InvalidLogonAttempts.md)
```
NAME
    Get-InvalidLogonAttempts
    
SYNOPSIS
    Return a list of invalid logon attempts.
    
    
SYNTAX
    Get-InvalidLogonAttempts [-ComputerName] <System.Object> [[-LogName] <System.Object>] [[-EventID] <System.Object>] [<CommonParameters>]
    
    
DESCRIPTION
    This function queries the security log of a given computer and retrieves Event ID 4625, failed logon attempt.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-InvalidLogonAttempts.md#get-invalidlogonattempts

REMARKS
    To see the examples, type: "get-help Get-InvalidLogonAttempts -examples".
    For more information, type: "get-help Get-InvalidLogonAttempts -detailed".
    For technical information, type: "get-help Get-InvalidLogonAttempts -full".
    For online help, type: "get-help Get-InvalidLogonAttempts -online"
```
## [New-LocalUser](docs/New-LocalUser.md)
```
NAME
    New-LocalUser
    
SYNOPSIS
    Create a new user account on the local computer.
    
    
SYNTAX
    New-LocalUser [-ComputerName] <System.String> [-User] <System.String> [-Password] <System.Security.SecureString> [[-Description] <System.String>] [-Confirm] [-WhatIf] [<CommonParameters>]
    
    
DESCRIPTION
    Creates a user named MyUserAccount on MyComputer.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/New-LocalUser.md#new-localuser

REMARKS
    To see the examples, type: "get-help New-LocalUser -examples".
    For more information, type: "get-help New-LocalUser -detailed".
    For technical information, type: "get-help New-LocalUser -full".
    For online help, type: "get-help New-LocalUser -online"
```
## [Remove-LocalUser](docs/Remove-LocalUser.md)
```
NAME
    Remove-LocalUser
    
SYNOPSIS
    Delete a user account from the local computer.
    
    
SYNTAX
    Remove-LocalUser [-ComputerName] <System.Object> [-UserName] <System.Object> [-Confirm] [-WhatIf] [<CommonParameters>]
    
    
DESCRIPTION
    Basic syntax of the command.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Remove-LocalUser.md#remove-localuser

REMARKS
    To see the examples, type: "get-help Remove-LocalUser -examples".
    For more information, type: "get-help Remove-LocalUser -detailed".
    For technical information, type: "get-help Remove-LocalUser -full".
    For online help, type: "get-help Remove-LocalUser -online"
```
## [Get-LocalUserAccounts](docs/Get-LocalUserAccounts.md)
```
NAME
    Get-LocalUserAccounts
    
SYNOPSIS
    Return a list of local user accounts.
    
    
SYNTAX
    Get-LocalUserAccounts [[-ComputerName] <System.String>] [[-Credentials] <System.Management.Automation.PSCredential>] [<CommonParameters>]
    
    
DESCRIPTION
    This function returns the Name and SID of any local user accounts that are found on the remote computer.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-LocalUserAccounts.md#get-localuseraccounts

REMARKS
    To see the examples, type: "get-help Get-LocalUserAccounts -examples".
    For more information, type: "get-help Get-LocalUserAccounts -detailed".
    For technical information, type: "get-help Get-LocalUserAccounts -full".
    For online help, type: "get-help Get-LocalUserAccounts -online"
```
## [Add-LocalUserToGroup](docs/Add-LocalUserToGroup.md)
```
NAME
    Add-LocalUserToGroup
    
SYNOPSIS
    Add an existing user to a local group.
    
    
SYNTAX
    Add-LocalUserToGroup [-ComputerName] <System.String> [-User] <System.String> [-Group] <System.String> [<CommonParameters>]
    
    
DESCRIPTION
    This function will add an existing user to an existing group.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Add-LocalUserToGroup.md#add-localusertogroup

REMARKS
    To see the examples, type: "get-help Add-LocalUserToGroup -examples".
    For more information, type: "get-help Add-LocalUserToGroup -detailed".
    For technical information, type: "get-help Add-LocalUserToGroup -full".
    For online help, type: "get-help Add-LocalUserToGroup -online"
```
## [Get-MappedDrives](docs/Get-MappedDrives.md)
```
NAME
    Get-MappedDrives
    
SYNOPSIS
    Return a list of mapped network drives on the computer
    
    
SYNTAX
    Get-MappedDrives [[-ComputerName] <System.String>] [[-Credentials] <System.Management.Automation.PSCredential>] [<CommonParameters>]
    
    
DESCRIPTION
    This function returns a list of mapped network drives from the local or remote computer.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-MappedDrives.md#get-mappeddrives

REMARKS
    To see the examples, type: "get-help Get-MappedDrives -examples".
    For more information, type: "get-help Get-MappedDrives -detailed".
    For technical information, type: "get-help Get-MappedDrives -full".
    For online help, type: "get-help Get-MappedDrives -online"
```
## [Get-Namespace](docs/Get-Namespace.md)
```
NAME
    Get-Namespace
    
SYNOPSIS
    Return a collection of classes from a namespace
    
    
SYNTAX
    Get-Namespace [-Namespace] <System.String> [-ComputerName] <System.String> [<CommonParameters>]
    
    
DESCRIPTION
    This function will return a collection of classes from the provided namespace. This method uses SWbemLocator to connect to a computer, the resulting SWbemServices object is used to return the SubclassesOf() the given namespace.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-Namespace.md#get-namespace

REMARKS
    To see the examples, type: "get-help Get-Namespace -examples".
    For more information, type: "get-help Get-Namespace -detailed".
    For technical information, type: "get-help Get-Namespace -full".
    For online help, type: "get-help Get-Namespace -online"
```
## [Get-NetShare](docs/Get-NetShare.md)
```
NAME
    Get-NetShare
    
SYNOPSIS
    Return a list of shares without using WMI
    
    
SYNTAX
    Get-NetShare [-ComputerName] <System.String> [-Type] <System.String> [<CommonParameters>]
    
    
DESCRIPTION
    This function returns a list of shares using the old net view command. This works well in situations where a fierwall may be blocking access.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-NetShare.md#get-netshare

REMARKS
    To see the examples, type: "get-help Get-NetShare -examples".
    For more information, type: "get-help Get-NetShare -detailed".
    For technical information, type: "get-help Get-NetShare -full".
    For online help, type: "get-help Get-NetShare -online"
```
## [Get-NonStandardServiceAccount](docs/Get-NonStandardServiceAccount.md)
```
NAME
    Get-NonStandardServiceAccount
    
SYNOPSIS
    Return a list of services using Non-Standard accounts.
    
    
SYNTAX
    Get-NonStandardServiceAccount [[-Computer] <System.String>] [[-Credentials] <System.Management.Automation.PSCredential>] [[-Filter] <System.String>] [<CommonParameters>]
    
    
DESCRIPTION
    This function returns a list of services from local or remote coputers that have non-standard user accounts for logon credentials.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-NonStandardServiceAccount.md#get-nonstandardserviceaccount

REMARKS
    To see the examples, type: "get-help Get-NonStandardServiceAccount -examples".
    For more information, type: "get-help Get-NonStandardServiceAccount -detailed".
    For technical information, type: "get-help Get-NonStandardServiceAccount -full".
    For online help, type: "get-help Get-NonStandardServiceAccount -online"
```
## [Get-OpenFiles](docs/Get-OpenFiles.md)
```
NAME
    Get-OpenFiles
    
SYNOPSIS
    Get a list of files open on the server
    
    
SYNTAX
    Get-OpenFiles [[-ComputerName] <System.Object>] [<CommonParameters>]
    
    
DESCRIPTION
    This function returns a list of files open on a given server. The output is similar to that of the Manage Open Files from the Share and Storage Management console.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-OpenFiles.md#get-openfiles

REMARKS
    To see the examples, type: "get-help Get-OpenFiles -examples".
    For more information, type: "get-help Get-OpenFiles -detailed".
    For technical information, type: "get-help Get-OpenFiles -full".
    For online help, type: "get-help Get-OpenFiles -online"
```
## [Get-OpenSessions](docs/Get-OpenSessions.md)
```
NAME
    Get-OpenSessions
    
SYNOPSIS
    Return a list of open sessions
    
    
SYNTAX
    Get-OpenSessions [[-ComputerName] <System.Object>] [<CommonParameters>]
    
    
DESCRIPTION
    This function returns a list of open session on a given server. The output is similar to that of the Manage Open Sessions dialog in the Share and Storage Management console.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-OpenSessions.md#get-opensessions

REMARKS
    To see the examples, type: "get-help Get-OpenSessions -examples".
    For more information, type: "get-help Get-OpenSessions -detailed".
    For technical information, type: "get-help Get-OpenSessions -full".
    For online help, type: "get-help Get-OpenSessions -online"
```
## [Get-PaperCutLogs](docs/Get-PaperCutLogs.md)
```
NAME
    Get-PaperCutLogs
    
SYNOPSIS
    Get PaperCut logs from all print servers
    
    
SYNTAX
    Get-PaperCutLogs [[-PrintServers] <System.Object>] [<CommonParameters>]
    
    
DESCRIPTION
    Return the PaperCut logs from all print servers.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PaperCutLogs.md#get-papercutlogs

REMARKS
    To see the examples, type: "get-help Get-PaperCutLogs -examples".
    For more information, type: "get-help Get-PaperCutLogs -detailed".
    For technical information, type: "get-help Get-PaperCutLogs -full".
    For online help, type: "get-help Get-PaperCutLogs -online"
```
## [Set-Pass](docs/Set-Pass.md)
```
NAME
    Set-Pass
    
SYNOPSIS
    Change the password of an existing user account.
    
    
SYNTAX
    Set-Pass [-ComputerName] <System.String> [-UserName] <System.String> [-Password] <System.Security.SecureString> [-Confirm] [-WhatIf] [<CommonParameters>]
    
    
DESCRIPTION
    This function will change the password for an existing user account.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Set-Pass.md#set-pass

REMARKS
    To see the examples, type: "get-help Set-Pass -examples".
    For more information, type: "get-help Set-Pass -detailed".
    For technical information, type: "get-help Set-Pass -full".
    For online help, type: "get-help Set-Pass -online"
```
## [New-Password](docs/New-Password.md)
```
NAME
    New-Password
    
SYNOPSIS
    Create a new password
    
    
SYNTAX
    New-Password [[-Length] <System.Int32>] [[-Count] <System.Int32>] [-asSecureString] [-Strong] [-Confirm] [-WhatIf] [<CommonParameters>]
    
    
DESCRIPTION
    This function creates a password using the cryptographic Random Number Generator see the MSDN link for more details.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/New-Password.md#new-password
    PowerShell Password Generator http://www.peterprovost.org/blog/2007/06/22/Quick-n-Dirty-PowerShell-Password-Generator/
    MSDN RNG Crypto Service Provider http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider.aspx

REMARKS
    To see the examples, type: "get-help New-Password -examples".
    For more information, type: "get-help New-Password -detailed".
    For technical information, type: "get-help New-Password -full".
    For online help, type: "get-help New-Password -online"
```
## [Get-PendingUpdates](docs/Get-PendingUpdates.md)
```
NAME
    Get-PendingUpdates
    
SYNOPSIS
    Retrieves the updates waiting to be installed from WSUS
    
    
SYNTAX
    Get-PendingUpdates [[-ComputerName] <System.String>] [<CommonParameters>]
    
    
DESCRIPTION
    Retrieves the updates that are available to install on the local system
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PendingUpdates.md#get-pendingupdates

REMARKS
    To see the examples, type: "get-help Get-PendingUpdates -examples".
    For more information, type: "get-help Get-PendingUpdates -detailed".
    For technical information, type: "get-help Get-PendingUpdates -full".
    For online help, type: "get-help Get-PendingUpdates -online"
```
## [Get-PrinterLogs](docs/Get-PrinterLogs.md)
```
NAME
    Get-PrinterLogs
    
SYNOPSIS
    Get a log of all printing from a given server.
    
    
SYNTAX
    Get-PrinterLogs [[-LogName] <System.Object>] [-ComputerName] <System.Object> [<CommonParameters>]
    
    
DESCRIPTION
    This function will return a log of all the printing that has occurred on a given print server.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PrinterLogs.md#get-printerlogs

REMARKS
    To see the examples, type: "get-help Get-PrinterLogs -examples".
    For more information, type: "get-help Get-PrinterLogs -detailed".
    For technical information, type: "get-help Get-PrinterLogs -full".
    For online help, type: "get-help Get-PrinterLogs -online"
```
## [Connect-Rdp](docs/Connect-Rdp.md)
```
NAME
    Connect-Rdp
    
SYNOPSIS
    Connect to one or more computers over RDP
    
    
SYNTAX
    Connect-Rdp [-ComputerName] <System.Object> [[-Credential] <System.Management.Automation.PSCredential>] [<CommonParameters>]
    
    
DESCRIPTION
    To securely cache login credentials, you can use the command line utility cmdkey.exe. With this utility, you can save a username and a password for a given remote connection. Windows will then securely cache the information and 
    automatically use it when needed.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Connect-Rdp.md#connect-rdp
    Automatic Remote Desktop onnection http://www.powershellmagazine.com/2014/04/18/automatic-remote-desktop-connection/

REMARKS
    To see the examples, type: "get-help Connect-Rdp -examples".
    For more information, type: "get-help Connect-Rdp -detailed".
    For technical information, type: "get-help Connect-Rdp -full".
    For online help, type: "get-help Connect-Rdp -online"
```
## [Get-RDPLoginEvents](docs/Get-RDPLoginEvents.md)
```
NAME
    Get-RDPLoginEvents
    
SYNOPSIS
    Return Remote Desktop login attempts
    
    
SYNTAX
    Get-RDPLoginEvents [-ComputerName] <System.Object> [[-Credentials] <System.Management.Automation.PSCredential>] [<CommonParameters>]
    
    
DESCRIPTION
    This function returns login attempts from the Microsoft Windows TerminalServices RemoteConnectionManager log. The specific events are logged as EventID 1149, and they are logged whether or not the user actually gets to the desktop.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-RDPLoginEvents.md#Get-rdploginevents

REMARKS
    To see the examples, type: "get-help Get-RDPLoginEvents -examples".
    For more information, type: "get-help Get-RDPLoginEvents -detailed".
    For technical information, type: "get-help Get-RDPLoginEvents -full".
    For online help, type: "get-help Get-RDPLoginEvents -online"
```
## [Grant-RegistryPermission](docs/Grant-RegistryPermission.md)
```
NAME
    Grant-RegistryPermission
    
SYNOPSIS
    Grant permissions on registry paths
    
    
SYNTAX
    Grant-RegistryPermission [-Path] <System.String> [-Principal] <System.String> [-Rights] {QueryValues | SetValue | CreateSubKey | EnumerateSubKeys | Notify | CreateLink | Delete | ReadPermissions | WriteKey | ExecuteKey | ReadKey | 
    ChangePermissions | TakeOwnership | FullControl} [[-Inheritance] {None | ContainerInherit | ObjectInherit}] [[-Propagation] {None | NoPropagateInherit | InheritOnly}] [<CommonParameters>]
    
    
DESCRIPTION
    This function allows you to set permissions on registry paths on a computer. Using the parameters you can specify the rights, inheritance and propagation of the rights.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Grant-RegistryPermission.md#grant-registrypermission
    Grant Registry Permissions http://www.iheartpowershell.com/2011/09/grant-registry-permissions.html
    MSDN RegistryAccessRule http://msdn.microsoft.com/en-us/library/ms147899(v=vs.110).aspx
    MSDN RegistryRights http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights(v=vs.110).aspx
    MSDN ACL Inheritance http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.inheritanceflags(v=vs.110).aspx
    MSDN ACL Propagation http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.propagationflags(v=vs.110).aspx

REMARKS
    To see the examples, type: "get-help Grant-RegistryPermission -examples".
    For more information, type: "get-help Grant-RegistryPermission -detailed".
    For technical information, type: "get-help Grant-RegistryPermission -full".
    For online help, type: "get-help Grant-RegistryPermission -online"
```
## [New-ScheduledTask](docs/New-ScheduledTask.md)
```
NAME
    New-ScheduledTask
    
SYNOPSIS
    Create a Scheduled Task on a computer.
    
    
SYNTAX
    New-ScheduledTask [-TaskName] <System.String> [-TaskRun] <System.String> [-TaskSchedule] <System.String> [-StartTime] <System.String> [-StartDate] <System.String> [-TaskUser] <System.String> [-Server] <System.String> [-Confirm] 
    [-WhatIf] [<CommonParameters>]
    
    
DESCRIPTION
    Create a Scheduled Task on a local or remote computer.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/New-ScheduledTask.md#new-scheduledtask

REMARKS
    To see the examples, type: "get-help New-ScheduledTask -examples".
    For more information, type: "get-help New-ScheduledTask -detailed".
    For technical information, type: "get-help New-ScheduledTask -full".
    For online help, type: "get-help New-ScheduledTask -online"
```
## [Get-ServiceTag](docs/Get-ServiceTag.md)
```
NAME
    Get-ServiceTag
    
SYNOPSIS
    Get the serial number (Dell ServiceTag) from Win32_BIOS
    
    
SYNTAX
    Get-ServiceTag [[-ComputerName] <System.Object>] [<CommonParameters>]
    
    
DESCRIPTION
    An example showing the only parameter.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-ServiceTag.md#get-servicetag

REMARKS
    To see the examples, type: "get-help Get-ServiceTag -examples".
    For more information, type: "get-help Get-ServiceTag -detailed".
    For technical information, type: "get-help Get-ServiceTag -full".
    For online help, type: "get-help Get-ServiceTag -online"
```
## [Set-ShutdownMethod](docs/Set-ShutdownMethod.md)
```
NAME
    Set-ShutdownMethod
    
SYNOPSIS
    Execute the Win32Shutdown method on a remote computer
    
    
SYNTAX
    Set-ShutdownMethod [-ComputerName] <System.String> [[-Credentials] <System.Management.Automation.PSCredential>] [[-ShutdownMethod] <System.Int32>] [-Confirm] [-WhatIf] [<CommonParameters>]
    
    
DESCRIPTION
    This function executes the Win32Shutdown method on a remote computer. This can be either an IP, NetBIOS name or FQDN. Use the ShutdownMethod param to specify the type of shutdown.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Set-ShutdownMethod.md#set-shutdownmethod

REMARKS
    To see the examples, type: "get-help Set-ShutdownMethod -examples".
    For more information, type: "get-help Set-ShutdownMethod -detailed".
    For technical information, type: "get-help Set-ShutdownMethod -full".
    For online help, type: "get-help Set-ShutdownMethod -online"
```
## [Remove-UserFromLocalGroup](docs/Remove-UserFromLocalGroup.md)
```
NAME
    Remove-UserFromLocalGroup
    
SYNOPSIS
    Removes a user/group from a local computer group.
    
    
SYNTAX
    Remove-UserFromLocalGroup [-ComputerName] <System.String> [-UserName] <System.String> [-GroupName] <System.String> [-Confirm] [-WhatIf] [<CommonParameters>]
    
    
DESCRIPTION
    This example removes a user from the local users group.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Remove-UserFromLocalGroup.md#remove-userfromlocalgroup
    https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Remove-UserFromLocalGroup https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Remove-UserFromLocalGroup

REMARKS
    To see the examples, type: "get-help Remove-UserFromLocalGroup -examples".
    For more information, type: "get-help Remove-UserFromLocalGroup -detailed".
    For technical information, type: "get-help Remove-UserFromLocalGroup -full".
    For online help, type: "get-help Remove-UserFromLocalGroup -online"
```
## [Get-WinEventTail](docs/Get-WinEventTail.md)
```
NAME
    Get-WinEventTail
    
SYNOPSIS
    A tail cmdlet for Eventlogs
    
    
SYNTAX
    Get-WinEventTail [[-LogName] <System.String>] [[-ShowExisting] <System.Int32>] [<CommonParameters>]
    
    
DESCRIPTION
    This function will allow you to tail Windows Event Logs. You specify a Logname for either the original logs, Application, System and Security or the new format for the newer logs Microsoft-Windows-PowerShell/Operational
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-WinEventTail.md#get-wineventtail
    StackOverflow Question http://stackoverflow.com/questions/15262196/powershell-tail-windows-event-log-is-it-possible

REMARKS
    To see the examples, type: "get-help Get-WinEventTail -examples".
    For more information, type: "get-help Get-WinEventTail -detailed".
    For technical information, type: "get-help Get-WinEventTail -full".
    For online help, type: "get-help Get-WinEventTail -online"
```


