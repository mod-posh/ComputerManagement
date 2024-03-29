| Latest Version | Azure Pipelines | PowerShell Gallery | Github Release | Issues | Forks | License |
|-----------------|-----------------|----------------|----------------|----------------|----------------|----------------|
| ![Latest Version](https://img.shields.io/github/v/tag/mod-posh/ComputerManagement) | [![Build Status](https://dev.azure.com/patton-tech/mod-posh/_apis/build/status/mod-posh.ComputerManagement?repoName=mod-posh%2FComputerManagement&branchName=master)](https://dev.azure.com/patton-tech/mod-posh/_build/latest?definitionId=10&repoName=mod-posh%2FComputerManagement&branchName=master) | ![Powershell Gallery](https://img.shields.io/powershellgallery/dt/ComputerManagement) | ![Github Release](https://img.shields.io/github/downloads/mod-posh/ComputerManagement/total) | [![GitHub issues](https://img.shields.io/github/issues/mod-posh/ComputerManagement)](https://github.com/mod-posh/ComputerManagement/issues) | [![GitHub forks](https://img.shields.io/github/forks/mod-posh/ComputerManagement)](https://github.com/mod-posh/ComputerManagement/network) | [![GitHub license](https://img.shields.io/github/license/mod-posh/ComputerManagement)](https://github.com/mod-posh/ComputerManagement/blob/master/LICENSE)
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
    To see the examples, type: "Get-Help New-Credential -Examples"
    For more information, type: "Get-Help New-Credential -Detailed"
    For technical information, type: "Get-Help New-Credential -Full"
    For online help, type: "Get-Help New-Credential -Online"
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
    To see the examples, type: "Get-Help Get-DiskUsage -Examples"
    For more information, type: "Get-Help Get-DiskUsage -Detailed"
    For technical information, type: "Get-Help Get-DiskUsage -Full"
    For online help, type: "Get-Help Get-DiskUsage -Online"
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
    To see the examples, type: "Get-Help Backup-EventLog -Examples"
    For more information, type: "Get-Help Backup-EventLog -Detailed"
    For technical information, type: "Get-Help Backup-EventLog -Full"
    For online help, type: "Get-Help Backup-EventLog -Online"
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
    To see the examples, type: "Get-Help Export-EventLog -Examples"
    For more information, type: "Get-Help Export-EventLog -Detailed"
    For technical information, type: "Get-Help Export-EventLog -Full"
    For online help, type: "Get-Help Export-EventLog -Online"
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
    To see the examples, type: "Get-Help Get-InvalidLogonAttempt -Examples"
    For more information, type: "Get-Help Get-InvalidLogonAttempt -Detailed"
    For technical information, type: "Get-Help Get-InvalidLogonAttempt -Full"
    For online help, type: "Get-Help Get-InvalidLogonAttempt -Online"
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
    To see the examples, type: "Get-Help Get-MappedDrive -Examples"
    For more information, type: "Get-Help Get-MappedDrive -Detailed"
    For technical information, type: "Get-Help Get-MappedDrive -Full"
    For online help, type: "Get-Help Get-MappedDrive -Online"
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
    To see the examples, type: "Get-Help Get-NetShare -Examples"
    For more information, type: "Get-Help Get-NetShare -Detailed"
    For technical information, type: "Get-Help Get-NetShare -Full"
    For online help, type: "Get-Help Get-NetShare -Online"
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
    To see the examples, type: "Get-Help Get-NonStandardServiceAccount -Examples"
    For more information, type: "Get-Help Get-NonStandardServiceAccount -Detailed"
    For technical information, type: "Get-Help Get-NonStandardServiceAccount -Full"
    For online help, type: "Get-Help Get-NonStandardServiceAccount -Online"
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
    To see the examples, type: "Get-Help Get-OpenFile -Examples"
    For more information, type: "Get-Help Get-OpenFile -Detailed"
    For technical information, type: "Get-Help Get-OpenFile -Full"
    For online help, type: "Get-Help Get-OpenFile -Online"
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
    To see the examples, type: "Get-Help Get-OpenSession -Examples"
    For more information, type: "Get-Help Get-OpenSession -Detailed"
    For technical information, type: "Get-Help Get-OpenSession -Full"
    For online help, type: "Get-Help Get-OpenSession -Online"
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
    To see the examples, type: "Get-Help New-Password -Examples"
    For more information, type: "Get-Help New-Password -Detailed"
    For technical information, type: "Get-Help New-Password -Full"
    For online help, type: "Get-Help New-Password -Online"
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
    To see the examples, type: "Get-Help Get-PendingUpdate -Examples"
    For more information, type: "Get-Help Get-PendingUpdate -Detailed"
    For technical information, type: "Get-Help Get-PendingUpdate -Full"
    For online help, type: "Get-Help Get-PendingUpdate -Online"
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
    To see the examples, type: "Get-Help Get-PrinterLog -Examples"
    For more information, type: "Get-Help Get-PrinterLog -Detailed"
    For technical information, type: "Get-Help Get-PrinterLog -Full"
    For online help, type: "Get-Help Get-PrinterLog -Online"
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
    To see the examples, type: "Get-Help Connect-Rdp -Examples"
    For more information, type: "Get-Help Connect-Rdp -Detailed"
    For technical information, type: "Get-Help Connect-Rdp -Full"
    For online help, type: "Get-Help Connect-Rdp -Online"
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
    To see the examples, type: "Get-Help Get-RDPLoginEvent -Examples"
    For more information, type: "Get-Help Get-RDPLoginEvent -Detailed"
    For technical information, type: "Get-Help Get-RDPLoginEvent -Full"
    For online help, type: "Get-Help Get-RDPLoginEvent -Online"
```
## [Grant-RegistryPermission](docs/Grant-RegistryPermission.md)
```
NAME
    Grant-RegistryPermission
    
SYNOPSIS
    Grant permissions on registry paths
    
    
SYNTAX
    Grant-RegistryPermission [-Path] <String> [-Principal] <String> [-Rights] {QueryValues | SetValue | CreateSubKey | EnumerateSubKeys | Notify | CreateLink | Delete | ReadPermissions | WriteKey | ExecuteKey | ReadKey | ChangePermissions | TakeOwnership | FullControl} [[-Inheritance] {None | ContainerInherit | ObjectInherit}] [[-Propagation] {None | NoPropagateInherit | InheritOnly}] [<CommonParameters>]
    
    
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
    To see the examples, type: "Get-Help Grant-RegistryPermission -Examples"
    For more information, type: "Get-Help Grant-RegistryPermission -Detailed"
    For technical information, type: "Get-Help Grant-RegistryPermission -Full"
    For online help, type: "Get-Help Grant-RegistryPermission -Online"
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
    To see the examples, type: "Get-Help Get-ServiceTag -Examples"
    For more information, type: "Get-Help Get-ServiceTag -Detailed"
    For technical information, type: "Get-Help Get-ServiceTag -Full"
    For online help, type: "Get-Help Get-ServiceTag -Online"
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
    To see the examples, type: "Get-Help Get-WinEventTail -Examples"
    For more information, type: "Get-Help Get-WinEventTail -Detailed"
    For technical information, type: "Get-Help Get-WinEventTail -Full"
    For online help, type: "Get-Help Get-WinEventTail -Online"
```

