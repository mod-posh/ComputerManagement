| Latest Version | Azure Pipelines | PowerShell Gallery | Github Release | Issues | Forks | License |
|-----------------|-----------------|----------------|----------------|----------------|----------------|----------------|
| ![Latest Version](https://img.shields.io/github/v/tag/mod-posh/ComputerManagement) | [![Build Status](https://dev.azure.com/patton-tech/Mod-Posh/_apis/build/status/mod-posh.ComputerManagement?repoName=mod-posh%2FComputerManagement&branchName=master)](https://dev.azure.com/patton-tech/Mod-Posh/_build/latest?definitionId=10&repoName=mod-posh%2FComputerManagement&branchName=master) | ![Powershell Gallery](https://img.shields.io/powershellgallery/dt/ComputerManagement) | ![Github Release](https://img.shields.io/github/downloads/mod-posh/ComputerManagement/total) | [![GitHub issues](https://img.shields.io/github/issues/mod-posh/ComputerManagement)](https://github.com/mod-posh/ComputerManagement/issues) | [![GitHub forks](https://img.shields.io/github/forks/mod-posh/ComputerManagement)](https://github.com/mod-posh/ComputerManagement/network) | [![GitHub license](https://img.shields.io/github/license/mod-posh/ComputerManagement)](https://github.com/mod-posh/ComputerManagement/blob/master/LICENSE)
## [New-Credential](docs/New-Credential.md)
```

NAME
    New-Credential
    
SYNOPSIS
    Create a Credential Object
    
    
SYNTAX
    New-Credential [-Username] <String> [-Password] <SecureString> [-Confirm] [-WhatIf] [<CommonParameters>]
    
    
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
    Get-DiskUsage [[-Path] <String>] [<CommonParameters>]
    
    
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
## [Backup-EventLog](docs/Backup-EventLog.md)
```
NAME
    Backup-EventLog
    
SYNOPSIS
    Backup Eventlogs from remote computer
    
    
SYNTAX
    Backup-EventLog [[-ComputerName] <String>] [[-LogPath] <String>] [[-BackupPath] <String>] [<CommonParameters>]
    
    
DESCRIPTION
    This function copies event log files from a remote computer to a backup location.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Backup-EventLog.md#backup-eventlog

REMARKS
    To see the examples, type: "get-help Backup-EventLog -examples".
    For more information, type: "get-help Backup-EventLog -detailed".
    For technical information, type: "get-help Backup-EventLog -full".
    For online help, type: "get-help Backup-EventLog -online"
```
## [Export-EventLog](docs/Export-EventLog.md)
```
NAME
    Export-EventLog
    
SYNOPSIS
    Export an Eventlog from a local or remote computer
    
    
SYNTAX
    Export-EventLog [[-ComputerName] <Object>] [[-Credential] <PSCredential>] [[-LogName] <Object>] [[-Destination] <Object>] [-ListLog] [<CommonParameters>]
    
    
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
## [Get-InvalidLogonAttempt](docs/Get-InvalidLogonAttempt.md)
```
NAME
    Get-InvalidLogonAttempt
    
SYNOPSIS
    Return a list of invalid logon attempts.
    
    
SYNTAX
    Get-InvalidLogonAttempt [-ComputerName] <Object> [[-LogName] <Object>] [[-EventID] <Object>] [<CommonParameters>]
    
    
DESCRIPTION
    This function queries the security log of a given computer and retrieves Event ID 4625, failed logon attempt.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-InvalidLogonAttempt.md#get-invalidlogonattempt

REMARKS
    To see the examples, type: "get-help Get-InvalidLogonAttempt -examples".
    For more information, type: "get-help Get-InvalidLogonAttempt -detailed".
    For technical information, type: "get-help Get-InvalidLogonAttempt -full".
    For online help, type: "get-help Get-InvalidLogonAttempt -online"
```
## [Get-MappedDrive](docs/Get-MappedDrive.md)
```
NAME
    Get-MappedDrive
    
SYNOPSIS
    Return a list of mapped network drives on the computer
    
    
SYNTAX
    Get-MappedDrive [[-ComputerName] <String>] [[-Credentials] <PSCredential>] [<CommonParameters>]
    
    
DESCRIPTION
    This function returns a list of mapped network drives from the local or remote computer.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-MappedDrive.md#get-mappeddrive

REMARKS
    To see the examples, type: "get-help Get-MappedDrive -examples".
    For more information, type: "get-help Get-MappedDrive -detailed".
    For technical information, type: "get-help Get-MappedDrive -full".
    For online help, type: "get-help Get-MappedDrive -online"
```
## [Get-NetShare](docs/Get-NetShare.md)
```
NAME
    Get-NetShare
    
SYNOPSIS
    Return a list of shares without using WMI
    
    
SYNTAX
    Get-NetShare [-ComputerName] <String> [-Type] <String> [<CommonParameters>]
    
    
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
    Get-NonStandardServiceAccount [[-Computer] <String>] [[-Credentials] <PSCredential>] [[-Filter] <String>] [<CommonParameters>]
    
    
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
## [Get-OpenFile](docs/Get-OpenFile.md)
```
NAME
    Get-OpenFile
    
SYNOPSIS
    Get a list of files open on the server
    
    
SYNTAX
    Get-OpenFile [[-ComputerName] <Object>] [<CommonParameters>]
    
    
DESCRIPTION
    This function returns a list of files open on a given server. The output is similar to that of the Manage Open Files from the Share and Storage Management console.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-OpenFile.md#get-openfile

REMARKS
    To see the examples, type: "get-help Get-OpenFile -examples".
    For more information, type: "get-help Get-OpenFile -detailed".
    For technical information, type: "get-help Get-OpenFile -full".
    For online help, type: "get-help Get-OpenFile -online"
```
## [Get-OpenSession](docs/Get-OpenSession.md)
```
NAME
    Get-OpenSession
    
SYNOPSIS
    Return a list of open sessions
    
    
SYNTAX
    Get-OpenSession [[-ComputerName] <Object>] [<CommonParameters>]
    
    
DESCRIPTION
    This function returns a list of open session on a given server. The output is similar to that of the Manage Open Sessions dialog in the Share and Storage Management console.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-OpenSession.md#get-opensession

REMARKS
    To see the examples, type: "get-help Get-OpenSession -examples".
    For more information, type: "get-help Get-OpenSession -detailed".
    For technical information, type: "get-help Get-OpenSession -full".
    For online help, type: "get-help Get-OpenSession -online"
```
## [New-Password](docs/New-Password.md)
```
NAME
    New-Password
    
SYNOPSIS
    Create a new password
    
    
SYNTAX
    New-Password [[-Length] <Int32>] [[-Count] <Int32>] [-asSecureString] [-Strong] [-Confirm] [-WhatIf] [<CommonParameters>]
    
    
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
## [Get-PendingUpdate](docs/Get-PendingUpdate.md)
```
NAME
    Get-PendingUpdate
    
SYNOPSIS
    Retrieves the updates waiting to be installed from WSUS
    
    
SYNTAX
    Get-PendingUpdate [[-ComputerName] <String>] [<CommonParameters>]
    
    
DESCRIPTION
    Retrieves the updates that are available to install on the local system
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PendingUpdate.md#get-pendingupdate

REMARKS
    To see the examples, type: "get-help Get-PendingUpdate -examples".
    For more information, type: "get-help Get-PendingUpdate -detailed".
    For technical information, type: "get-help Get-PendingUpdate -full".
    For online help, type: "get-help Get-PendingUpdate -online"
```
## [Get-PrinterLog](docs/Get-PrinterLog.md)
```
NAME
    Get-PrinterLog
    
SYNOPSIS
    Get a log of all printing from a given server.
    
    
SYNTAX
    Get-PrinterLog [[-LogName] <Object>] [-ComputerName] <Object> [<CommonParameters>]
    
    
DESCRIPTION
    This function will return a log of all the printing that has occurred on a given print server.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PrinterLog.md#get-printerlog

REMARKS
    To see the examples, type: "get-help Get-PrinterLog -examples".
    For more information, type: "get-help Get-PrinterLog -detailed".
    For technical information, type: "get-help Get-PrinterLog -full".
    For online help, type: "get-help Get-PrinterLog -online"
```
## [Connect-Rdp](docs/Connect-Rdp.md)
```
NAME
    Connect-Rdp
    
SYNOPSIS
    Connect to one or more computers over RDP
    
    
SYNTAX
    Connect-Rdp [-ComputerName] <Object> [[-Credential] <PSCredential>] [<CommonParameters>]
    
    
DESCRIPTION
    To securely cache login credentials, you can use the command line utility cmdkey.exe. With this utility, you can save a username and a password for a given remote connection. Windows will then securely cache the information and automatically use it when needed.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Connect-Rdp.md#connect-rdp
    Automatic Remote Desktop onnection http://www.powershellmagazine.com/2014/04/18/automatic-remote-desktop-connection/

REMARKS
    To see the examples, type: "get-help Connect-Rdp -examples".
    For more information, type: "get-help Connect-Rdp -detailed".
    For technical information, type: "get-help Connect-Rdp -full".
    For online help, type: "get-help Connect-Rdp -online"
```
## [Get-RDPLoginEvent](docs/Get-RDPLoginEvent.md)
```
NAME
    Get-RDPLoginEvent
    
SYNOPSIS
    Return Remote Desktop login attempts
    
    
SYNTAX
    Get-RDPLoginEvent [-ComputerName] <Object> [[-Credentials] <PSCredential>] [<CommonParameters>]
    
    
DESCRIPTION
    This function returns login attempts from the Microsoft Windows TerminalServices RemoteConnectionManager log. The specific events are logged as EventID 1149, and they are logged whether or not the user actually gets to the desktop.
    

RELATED LINKS
    Online Version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-RDPLoginEvent.md#Get-rdploginevent

REMARKS
    To see the examples, type: "get-help Get-RDPLoginEvent -examples".
    For more information, type: "get-help Get-RDPLoginEvent -detailed".
    For technical information, type: "get-help Get-RDPLoginEvent -full".
    For online help, type: "get-help Get-RDPLoginEvent -online"
```
## [Grant-RegistryPermission](docs/Grant-RegistryPermission.md)
```
NAME
    Grant-RegistryPermission
    
SYNOPSIS
    Grant permissions on registry paths
    
    
SYNTAX
    Grant-RegistryPermission [-Path] <String> [-Principal] <String> [-Rights] {QueryValues | SetValue | CreateSubKey | EnumerateSubKeys | Notify | CreateLink | Delete | ReadPermissions | WriteKey | ExecuteKey | ReadKey | ChangePermissions | TakeOwnership | FullControl} 
    [[-Inheritance] {None | ContainerInherit | ObjectInherit}] [[-Propagation] {None | NoPropagateInherit | InheritOnly}] [<CommonParameters>]
    
    
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
## [Get-ServiceTag](docs/Get-ServiceTag.md)
```
NAME
    Get-ServiceTag
    
SYNOPSIS
    Get the serial number (Dell ServiceTag) from Win32_BIOS
    
    
SYNTAX
    Get-ServiceTag [[-ComputerName] <Object>] [<CommonParameters>]
    
    
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
## [Get-WinEventTail](docs/Get-WinEventTail.md)
```
NAME
    Get-WinEventTail
    
SYNOPSIS
    A tail cmdlet for Eventlogs
    
    
SYNTAX
    Get-WinEventTail [[-LogName] <String>] [[-ShowExisting] <Int32>] [<CommonParameters>]
    
    
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


