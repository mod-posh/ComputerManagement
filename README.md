[![GitHub issues](https://img.shields.io/github/issues/mod-posh/ComputerManagement)](https://github.com/mod-posh/ComputerManagement/issues)
[![GitHub forks](https://img.shields.io/github/forks/mod-posh/ComputerManagement)](https://github.com/mod-posh/ComputerManagement/network)
[![GitHub license](https://img.shields.io/github/license/mod-posh/ComputerManagement)](https://github.com/mod-posh/ComputerManagement/blob/master/LICENSE)
## [Open-CdDrive](docs/Open-CdDrive.md)
```

NAME
    Open-CdDrive
    
SYNTAX
    Open-CdDrive [[-Drive] <string>]  [<CommonParameters>]
    

ALIASES
    None
    

REMARKS
    Get-Help cannot find the Help files for this cmdlet on this computer. It is displaying only partial help.
        -- To download and install Help files for the module that includes this cmdlet, use Update-Help.
        -- To view the Help topic for this cmdlet online, type: "Get-Help Open-CdDrive -Online" or 
           go to https://github.com/mod-posh/ComputerManagement/blob/master/docs/Open-CdDrive.md#open-cddrive.

```
## [Get-CimService](docs/Get-CimService.md)
```
NAME
    Get-CimService
    
SYNTAX
    Get-CimService [[-Computer] <string>] [[-Credential] <pscredential>] [[-State] <string>] [[-StartMode] <string>]  [<CommonParameters>]
    

ALIASES
    None
    

REMARKS
    Get-Help cannot find the Help files for this cmdlet on this computer. It is displaying only partial help.
        -- To download and install Help files for the module that includes this cmdlet, use Update-Help.
        -- To view the Help topic for this cmdlet online, type: "Get-Help Get-CimService -Online" or 
           go to https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-CimService.md#get-cimservice.

```
## [New-Credential](docs/New-Credential.md)
```

examples      : @{example=@{code=PS C:\> $Credential = New-Credential -Username user1 -Password (ConvertFrom-SecureString "P@ssw0rd" -AsPlainText -Force); remarks=System.Management.Automation.PSObject[]; title=-------------------------- Example 1 
                --------------------------}}
inputTypes    : @{inputType=@{type=@{name=None}; description=System.Management.Automation.PSObject[]}}
alertSet      : @{alert=System.Management.Automation.PSObject[]}
syntax        : @{syntaxItem=@{name=New-Credential; parameter=System.Management.Automation.PSObject[]}}
parameters    : @{parameter=System.Management.Automation.PSObject[]}
details       : @{description=System.Management.Automation.PSObject[]; verb=New; noun=Credential; name=New-Credential}
description   : {@{Text=This function creates a new Credential Object for use in Scripts or cmdlets.}}
relatedLinks  : @{navigationLink=@{uri=https://github.com/mod-posh/ComputerManagement/blob/master/docs/New-Credential.md#new-credential; linkText=Online Version:}}
returnValues  : @{returnValue=@{type=@{name=System.Object}; description=System.Management.Automation.PSObject[]}}
xmlns:maml    : http://schemas.microsoft.com/maml/2004/10
xmlns:command : http://schemas.microsoft.com/maml/dev/command/2004/10
xmlns:dev     : http://schemas.microsoft.com/maml/dev/2004/10
xmlns:MSHelp  : http://msdn.microsoft.com/mshelp
Name          : New-Credential
Category      : Function
Synopsis      : Create a Credential Object
Component     : 
Role          : 
Functionality : 
ModuleName    : ComputerManagement

```
## [Get-DiskUsage](docs/Get-DiskUsage.md)
```

examples      : @{example=System.Management.Automation.PSObject[]}
inputTypes    : 
alertSet      : @{alert=System.Management.Automation.PSObject[]}
syntax        : @{syntaxItem=@{name=Get-DiskUsage; parameter=@{Description=System.Management.Automation.PSObject[]; defaultValue=.; parameterValue=String; name=Path; type=@{name=String; uri=}; required=false; variableLength=true; globbing=false; pipelineInput=False; 
                position=1; aliases=none}}}
parameters    : @{parameter=@{Description=System.Management.Automation.PSObject[]; defaultValue=.; parameterValue=String; name=Path; type=@{name=String; uri=}; required=false; variableLength=true; globbing=false; pipelineInput=False; position=1; aliases=none}}
details       : @{description=System.Management.Automation.PSObject[]; verb=Get; noun=DiskUsage; name=Get-DiskUsage}
description   : {@{Text=This function returns the disk usage of a given path}}
relatedLinks  : @{navigationLink=@{uri=https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-DiskUsage.md#get-diskusage; linkText=Online Version:}}
returnValues  : 
xmlns:maml    : http://schemas.microsoft.com/maml/2004/10
xmlns:command : http://schemas.microsoft.com/maml/dev/command/2004/10
xmlns:dev     : http://schemas.microsoft.com/maml/dev/2004/10
xmlns:MSHelp  : http://msdn.microsoft.com/mshelp
Name          : Get-DiskUsage
Category      : Function
Synopsis      : Get the disk usage of a given path
Component     : 
Role          : 
Functionality : 
ModuleName    : ComputerManagement

```
## [Backup-EventLog](docs/Backup-EventLog.md)
```

examples      : @{example=@{code=Backup-EventLogs -ComputerName dc1; remarks=System.Management.Automation.PSObject[]; title=-------------------------- EXAMPLE 1 --------------------------}}
inputTypes    : 
alertSet      : @{alert=System.Management.Automation.PSObject[]}
syntax        : @{syntaxItem=@{name=Backup-EventLog; parameter=System.Management.Automation.PSObject[]}}
parameters    : @{parameter=System.Management.Automation.PSObject[]}
details       : @{description=System.Management.Automation.PSObject[]; verb=Backup; noun=EventLog; name=Backup-EventLog}
description   : {@{Text=This function copies event log files from a remote computer to a backup location.}}
relatedLinks  : @{navigationLink=@{uri=https://github.com/mod-posh/ComputerManagement/blob/master/docs/Backup-EventLog.md#backup-eventlog; linkText=Online Version:}}
returnValues  : 
xmlns:maml    : http://schemas.microsoft.com/maml/2004/10
xmlns:command : http://schemas.microsoft.com/maml/dev/command/2004/10
xmlns:dev     : http://schemas.microsoft.com/maml/dev/2004/10
xmlns:MSHelp  : http://msdn.microsoft.com/mshelp
Name          : Backup-EventLog
Category      : Function
Synopsis      : Backup Eventlogs from remote computer
Component     : 
Role          : 
Functionality : 
ModuleName    : ComputerManagement

```
## [Export-EventLog](docs/Export-EventLog.md)
```

examples      : @{example=System.Management.Automation.PSObject[]}
inputTypes    : 
alertSet      : @{alert=System.Management.Automation.PSObject[]}
syntax        : @{syntaxItem=@{name=Export-EventLog; parameter=System.Management.Automation.PSObject[]}}
parameters    : @{parameter=System.Management.Automation.PSObject[]}
details       : @{description=System.Management.Automation.PSObject[]; verb=Export; noun=EventLog; name=Export-EventLog}
description   : {@{Text=This function will export the logname you specify to the folder and filename that you provide. The exported file is in the native format for Event logs.
                }, @{Text=This function leverages the System.Diagnostics.Eventing.Reader class to export the log of the local or remote computer.}}
relatedLinks  : @{navigationLink=@{uri=https://github.com/mod-posh/ComputerManagement/blob/master/docs/Export-EventLog.md#export-eventlog; linkText=Online Version:}}
returnValues  : 
xmlns:maml    : http://schemas.microsoft.com/maml/2004/10
xmlns:command : http://schemas.microsoft.com/maml/dev/command/2004/10
xmlns:dev     : http://schemas.microsoft.com/maml/dev/2004/10
xmlns:MSHelp  : http://msdn.microsoft.com/mshelp
Name          : Export-EventLog
Category      : Function
Synopsis      : Export an Eventlog from a local or remote computer
Component     : 
Role          : 
Functionality : 
ModuleName    : ComputerManagement

```
## [Backup-EventLogs](docs/Backup-EventLogs.md)
```
NAME
    Backup-EventLogs
    
SYNTAX
    Backup-EventLogs [[-ComputerName] <string>] [[-LogPath] <string>] [[-BackupPath] <string>]  [<CommonParameters>]
    

ALIASES
    None
    

REMARKS
    Get-Help cannot find the Help files for this cmdlet on this computer. It is displaying only partial help.
        -- To download and install Help files for the module that includes this cmdlet, use Update-Help.
        -- To view the Help topic for this cmdlet online, type: "Get-Help Backup-EventLogs -Online" or 
           go to https://github.com/mod-posh/ComputerManagement/blob/master/docs/Backup-EventLogs.md#backup-eventlogs.

```
## [Get-InvalidLogonAttempt](docs/Get-InvalidLogonAttempt.md)
```

examples      : @{example=System.Management.Automation.PSObject[]}
inputTypes    : 
alertSet      : @{alert=System.Management.Automation.PSObject[]}
syntax        : @{syntaxItem=@{name=Get-InvalidLogonAttempt; parameter=System.Management.Automation.PSObject[]}}
parameters    : @{parameter=System.Management.Automation.PSObject[]}
details       : @{description=System.Management.Automation.PSObject[]; verb=Get; noun=InvalidLogonAttempt; name=Get-InvalidLogonAttempt}
description   : {@{Text=This function queries the security log of a given computer and retrieves Event ID 4625, failed logon attempt.}}
relatedLinks  : @{navigationLink=@{uri=https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-InvalidLogonAttempt.md#get-invalidlogonattempt; linkText=Online Version:}}
returnValues  : 
xmlns:maml    : http://schemas.microsoft.com/maml/2004/10
xmlns:command : http://schemas.microsoft.com/maml/dev/command/2004/10
xmlns:dev     : http://schemas.microsoft.com/maml/dev/2004/10
xmlns:MSHelp  : http://msdn.microsoft.com/mshelp
Name          : Get-InvalidLogonAttempt
Category      : Function
Synopsis      : Return a list of invalid logon attempts.
Component     : 
Role          : 
Functionality : 
ModuleName    : ComputerManagement

```
## [Get-InvalidLogonAttempts](docs/Get-InvalidLogonAttempts.md)
```
NAME
    Get-InvalidLogonAttempts
    
SYNTAX
    Get-InvalidLogonAttempts [-ComputerName] <Object> [[-LogName] <Object>] [[-EventID] <Object>]  [<CommonParameters>]
    

ALIASES
    None
    

REMARKS
    Get-Help cannot find the Help files for this cmdlet on this computer. It is displaying only partial help.
        -- To download and install Help files for the module that includes this cmdlet, use Update-Help.
        -- To view the Help topic for this cmdlet online, type: "Get-Help Get-InvalidLogonAttempts -Online" or 
           go to https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-InvalidLogonAttempts.md#get-invalidlogonattempts.

```
## [Get-MappedDrive](docs/Get-MappedDrive.md)
```

examples      : @{example=System.Management.Automation.PSObject[]}
inputTypes    : 
alertSet      : @{alert=System.Management.Automation.PSObject[]}
syntax        : @{syntaxItem=@{name=Get-MappedDrive; parameter=System.Management.Automation.PSObject[]}}
parameters    : @{parameter=System.Management.Automation.PSObject[]}
details       : @{description=System.Management.Automation.PSObject[]; verb=Get; noun=MappedDrive; name=Get-MappedDrive}
description   : {@{Text=This function returns a list of mapped network drives from the local or remote computer.}}
relatedLinks  : @{navigationLink=@{uri=https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-MappedDrive.md#get-mappeddrive; linkText=Online Version:}}
returnValues  : 
xmlns:maml    : http://schemas.microsoft.com/maml/2004/10
xmlns:command : http://schemas.microsoft.com/maml/dev/command/2004/10
xmlns:dev     : http://schemas.microsoft.com/maml/dev/2004/10
xmlns:MSHelp  : http://msdn.microsoft.com/mshelp
Name          : Get-MappedDrive
Category      : Function
Synopsis      : Return a list of mapped network drives on the computer
Component     : 
Role          : 
Functionality : 
ModuleName    : ComputerManagement

```
## [Get-MappedDrives](docs/Get-MappedDrives.md)
```
NAME
    Get-MappedDrives
    
SYNTAX
    Get-MappedDrives [[-ComputerName] <string>] [[-Credentials] <pscredential>]  [<CommonParameters>]
    

ALIASES
    None
    

REMARKS
    Get-Help cannot find the Help files for this cmdlet on this computer. It is displaying only partial help.
        -- To download and install Help files for the module that includes this cmdlet, use Update-Help.
        -- To view the Help topic for this cmdlet online, type: "Get-Help Get-MappedDrives -Online" or 
           go to https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-MappedDrives.md#get-mappeddrives.

```
## [Get-Namespace](docs/Get-Namespace.md)
```
NAME
    Get-Namespace
    
SYNTAX
    Get-Namespace [-Namespace] <string> [-ComputerName] <string>  [<CommonParameters>]
    

ALIASES
    None
    

REMARKS
    Get-Help cannot find the Help files for this cmdlet on this computer. It is displaying only partial help.
        -- To download and install Help files for the module that includes this cmdlet, use Update-Help.
        -- To view the Help topic for this cmdlet online, type: "Get-Help Get-Namespace -Online" or 
           go to https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-Namespace.md#get-namespace.

```
## [Get-NetShare](docs/Get-NetShare.md)
```

examples      : @{example=@{code=Get-NetShare -ComputerName server-01 -Type Print
                
                Server      Share   Path
                ------      -----   ----
                server-01   hp01    \\\\server-01\hp01
                server-01   hp02    \\\\server-01\hp02
                server-01   hp03    \\\\server-01\hp03; remarks=System.Management.Automation.PSObject[]; title=-------------------------- EXAMPLE 1 --------------------------}}
inputTypes    : 
alertSet      : @{alert=System.Management.Automation.PSObject[]}
syntax        : @{syntaxItem=@{name=Get-NetShare; parameter=System.Management.Automation.PSObject[]}}
parameters    : @{parameter=System.Management.Automation.PSObject[]}
details       : @{description=System.Management.Automation.PSObject[]; verb=Get; noun=NetShare; name=Get-NetShare}
description   : {@{Text=This function returns a list of shares using the old net view command. This works well in situations where a fierwall may be blocking access.}}
relatedLinks  : @{navigationLink=@{uri=https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-NetShare.md#get-netshare; linkText=Online Version:}}
returnValues  : 
xmlns:maml    : http://schemas.microsoft.com/maml/2004/10
xmlns:command : http://schemas.microsoft.com/maml/dev/command/2004/10
xmlns:dev     : http://schemas.microsoft.com/maml/dev/2004/10
xmlns:MSHelp  : http://msdn.microsoft.com/mshelp
Name          : Get-NetShare
Category      : Function
Synopsis      : Return a list of shares without using WMI
Component     : 
Role          : 
Functionality : 
ModuleName    : ComputerManagement

```
## [Get-NonStandardServiceAccount](docs/Get-NonStandardServiceAccount.md)
```

examples      : @{example=System.Management.Automation.PSObject[]}
inputTypes    : 
alertSet      : @{alert=System.Management.Automation.PSObject[]}
syntax        : @{syntaxItem=@{name=Get-NonStandardServiceAccount; parameter=System.Management.Automation.PSObject[]}}
parameters    : @{parameter=System.Management.Automation.PSObject[]}
details       : @{description=System.Management.Automation.PSObject[]; verb=Get; noun=NonStandardServiceAccount; name=Get-NonStandardServiceAccount}
description   : {@{Text=This function returns a list of services from local or remote coputers that have non-standard user accounts for logon credentials.}}
relatedLinks  : @{navigationLink=@{uri=https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-NonStandardServiceAccount.md#get-nonstandardserviceaccount; linkText=Online Version:}}
returnValues  : 
xmlns:maml    : http://schemas.microsoft.com/maml/2004/10
xmlns:command : http://schemas.microsoft.com/maml/dev/command/2004/10
xmlns:dev     : http://schemas.microsoft.com/maml/dev/2004/10
xmlns:MSHelp  : http://msdn.microsoft.com/mshelp
Name          : Get-NonStandardServiceAccount
Category      : Function
Synopsis      : Return a list of services using Non-Standard accounts.
Component     : 
Role          : 
Functionality : 
ModuleName    : ComputerManagement

```
## [Get-OpenFile](docs/Get-OpenFile.md)
```

examples      : @{example=@{code=Get-OpenFiles -ComputerName fs
                
                User          Path                              LockCount
                ----          ----                              ---------
                User1         F:\Users\User1\Documents\Data\...         0
                User2         P:\Public                                 0; remarks=System.Management.Automation.PSObject[]; title=-------------------------- EXAMPLE 1 --------------------------}}
inputTypes    : 
alertSet      : @{alert=System.Management.Automation.PSObject[]}
syntax        : @{syntaxItem=@{name=Get-OpenFile; parameter=@{Description=System.Management.Automation.PSObject[]; defaultValue=(hostname); parameterValue=Object; name=ComputerName; type=@{name=Object; uri=}; required=false; variableLength=true; globbing=false; 
                pipelineInput=False; position=1; aliases=none}}}
parameters    : @{parameter=@{Description=System.Management.Automation.PSObject[]; defaultValue=(hostname); parameterValue=Object; name=ComputerName; type=@{name=Object; uri=}; required=false; variableLength=true; globbing=false; pipelineInput=False; position=1; 
                aliases=none}}
details       : @{description=System.Management.Automation.PSObject[]; verb=Get; noun=OpenFile; name=Get-OpenFile}
description   : {@{Text=This function returns a list of files open on a given server. The output is similar to that of the Manage Open Files from the Share and Storage Management console.}}
relatedLinks  : @{navigationLink=@{uri=https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-OpenFile.md#get-openfile; linkText=Online Version:}}
returnValues  : 
xmlns:maml    : http://schemas.microsoft.com/maml/2004/10
xmlns:command : http://schemas.microsoft.com/maml/dev/command/2004/10
xmlns:dev     : http://schemas.microsoft.com/maml/dev/2004/10
xmlns:MSHelp  : http://msdn.microsoft.com/mshelp
Name          : Get-OpenFile
Category      : Function
Synopsis      : Get a list of files open on the server
Component     : 
Role          : 
Functionality : 
ModuleName    : ComputerManagement

```
## [Get-OpenFiles](docs/Get-OpenFiles.md)
```
NAME
    Get-OpenFiles
    
SYNTAX
    Get-OpenFiles [[-ComputerName] <Object>]  [<CommonParameters>]
    

ALIASES
    None
    

REMARKS
    Get-Help cannot find the Help files for this cmdlet on this computer. It is displaying only partial help.
        -- To download and install Help files for the module that includes this cmdlet, use Update-Help.
        -- To view the Help topic for this cmdlet online, type: "Get-Help Get-OpenFiles -Online" or 
           go to https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-OpenFiles.md#get-openfiles.

```
## [Get-OpenSession](docs/Get-OpenSession.md)
```

examples      : @{example=@{code=Get-OpenSessions -ComputerName fs
                
                User          Computer         ConnectTime     IdleTime
                ----          --------         -----------     --------
                user1         10.10.1.62              1615            1
                user2         10.10.1.156             7529           17; remarks=System.Management.Automation.PSObject[]; title=-------------------------- EXAMPLE 1 --------------------------}}
inputTypes    : 
alertSet      : @{alert=System.Management.Automation.PSObject[]}
syntax        : @{syntaxItem=@{name=Get-OpenSession; parameter=@{Description=System.Management.Automation.PSObject[]; defaultValue=(hostname); parameterValue=Object; name=ComputerName; type=@{name=Object; uri=}; required=false; variableLength=true; globbing=false; 
                pipelineInput=False; position=1; aliases=none}}}
parameters    : @{parameter=@{Description=System.Management.Automation.PSObject[]; defaultValue=(hostname); parameterValue=Object; name=ComputerName; type=@{name=Object; uri=}; required=false; variableLength=true; globbing=false; pipelineInput=False; position=1; 
                aliases=none}}
details       : @{description=System.Management.Automation.PSObject[]; verb=Get; noun=OpenSession; name=Get-OpenSession}
description   : {@{Text=This function returns a list of open session on a given server. The output is similar to that of the Manage Open Sessions dialog in the Share and Storage Management console.}}
relatedLinks  : @{navigationLink=@{uri=https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-OpenSession.md#get-opensession; linkText=Online Version:}}
returnValues  : 
xmlns:maml    : http://schemas.microsoft.com/maml/2004/10
xmlns:command : http://schemas.microsoft.com/maml/dev/command/2004/10
xmlns:dev     : http://schemas.microsoft.com/maml/dev/2004/10
xmlns:MSHelp  : http://msdn.microsoft.com/mshelp
Name          : Get-OpenSession
Category      : Function
Synopsis      : Return a list of open sessions
Component     : 
Role          : 
Functionality : 
ModuleName    : ComputerManagement

```
## [Get-OpenSessions](docs/Get-OpenSessions.md)
```
NAME
    Get-OpenSessions
    
SYNTAX
    Get-OpenSessions [[-ComputerName] <Object>]  [<CommonParameters>]
    

ALIASES
    None
    

REMARKS
    Get-Help cannot find the Help files for this cmdlet on this computer. It is displaying only partial help.
        -- To download and install Help files for the module that includes this cmdlet, use Update-Help.
        -- To view the Help topic for this cmdlet online, type: "Get-Help Get-OpenSessions -Online" or 
           go to https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-OpenSessions.md#get-opensessions.

```
## [Get-PaperCutLogs](docs/Get-PaperCutLogs.md)
```
NAME
    Get-PaperCutLogs
    
SYNTAX
    Get-PaperCutLogs [[-PrintServers] <Object>]  [<CommonParameters>]
    

ALIASES
    None
    

REMARKS
    Get-Help cannot find the Help files for this cmdlet on this computer. It is displaying only partial help.
        -- To download and install Help files for the module that includes this cmdlet, use Update-Help.
        -- To view the Help topic for this cmdlet online, type: "Get-Help Get-PaperCutLogs -Online" or 
           go to https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PaperCutLogs.md#get-papercutlogs.

```
## [Set-Pass](docs/Set-Pass.md)
```
NAME
    Set-Pass
    
SYNTAX
    Set-Pass [-ComputerName] <string> [-UserName] <string> [-Password] <securestring> [-WhatIf] [-Confirm]  [<CommonParameters>]
    

ALIASES
    None
    

REMARKS
    Get-Help cannot find the Help files for this cmdlet on this computer. It is displaying only partial help.
        -- To download and install Help files for the module that includes this cmdlet, use Update-Help.
        -- To view the Help topic for this cmdlet online, type: "Get-Help Set-Pass -Online" or 
           go to https://github.com/mod-posh/ComputerManagement/blob/master/docs/Set-Pass.md#set-pass.

```
## [New-Password](docs/New-Password.md)
```

examples      : @{example=@{code=PS C:\> New-Password -Length 64 -Count 5 -Strong
                
                Password
                --------
                UkQfV)RHwcQ3a)s8Z#QwSCLxlI*y28kEPmcQUVM2HrACf@PxRJDLk4ffge#1m_8j
                XfAwZOh_lrzLE8NwkSTPs5#LNkW4uZ0Wm_ST5UzERqhY45)HBpN$_@@MxDeLiosW
                h(BN(y^Gip&pU$KJpAAajgopQyoSbCn41m53mc__wV@q$DY5a$iN&O0fnf9hvO1&
                tXkFwY_pe(VIFf$R2^bKyKy)D_H6q^Nz7MgSDylXrV2GIkyiFVnvfbd9KENFuHQz
                &6LPlWRB$#yqD@!IEuJ9JcMTKrsA_t(AbWRGTLx@2Fw__j08n(TGi6wgPE6XlLWg; remarks=System.Management.Automation.PSObject[]; title=-------------------------- Example 1 --------------------------}}
inputTypes    : @{inputType=@{type=@{name=None}; description=System.Management.Automation.PSObject[]}}
alertSet      : @{alert=System.Management.Automation.PSObject[]}
syntax        : @{syntaxItem=@{name=New-Password; parameter=System.Management.Automation.PSObject[]}}
parameters    : @{parameter=System.Management.Automation.PSObject[]}
details       : @{description=System.Management.Automation.PSObject[]; verb=New; noun=Password; name=New-Password}
description   : {@{Text=This function creates a password using the cryptographic Random Number Generator see the MSDN link for more details.}}
relatedLinks  : @{navigationLink=System.Management.Automation.PSObject[]}
returnValues  : @{returnValue=@{type=@{name=System.Object[]}; description=System.Management.Automation.PSObject[]}}
xmlns:maml    : http://schemas.microsoft.com/maml/2004/10
xmlns:command : http://schemas.microsoft.com/maml/dev/command/2004/10
xmlns:dev     : http://schemas.microsoft.com/maml/dev/2004/10
xmlns:MSHelp  : http://msdn.microsoft.com/mshelp
Name          : New-Password
Category      : Function
Synopsis      : Create a new password
Component     : 
Role          : 
Functionality : 
ModuleName    : ComputerManagement

```
## [Get-PendingUpdate](docs/Get-PendingUpdate.md)
```

examples      : @{example=@{code=Get-PendingUpdates; remarks=System.Management.Automation.PSObject[]; title=-------------------------- EXAMPLE 1 --------------------------}}
inputTypes    : 
alertSet      : @{alert=System.Management.Automation.PSObject[]}
syntax        : @{syntaxItem=@{name=Get-PendingUpdate; parameter=@{Description=System.Management.Automation.PSObject[]; defaultValue=None; parameterValue=String; name=ComputerName; type=@{name=String; uri=}; required=false; variableLength=true; globbing=false; 
                pipelineInput=True (ByValue); position=1; aliases=none}}}
parameters    : @{parameter=@{Description=System.Management.Automation.PSObject[]; defaultValue=None; parameterValue=String; name=ComputerName; type=@{name=String; uri=}; required=false; variableLength=true; globbing=false; pipelineInput=True (ByValue); position=1; 
                aliases=none}}
details       : @{description=System.Management.Automation.PSObject[]; verb=Get; noun=PendingUpdate; name=Get-PendingUpdate}
description   : {@{Text=Retrieves the updates that are available to install on the local system}}
relatedLinks  : @{navigationLink=@{uri=https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PendingUpdate.md#get-pendingupdate; linkText=Online Version:}}
returnValues  : 
xmlns:maml    : http://schemas.microsoft.com/maml/2004/10
xmlns:command : http://schemas.microsoft.com/maml/dev/command/2004/10
xmlns:dev     : http://schemas.microsoft.com/maml/dev/2004/10
xmlns:MSHelp  : http://msdn.microsoft.com/mshelp
Name          : Get-PendingUpdate
Category      : Function
Synopsis      : Retrieves the updates waiting to be installed from WSUS
Component     : 
Role          : 
Functionality : 
ModuleName    : ComputerManagement

```
## [Get-PendingUpdates](docs/Get-PendingUpdates.md)
```
NAME
    Get-PendingUpdates
    
SYNTAX
    Get-PendingUpdates [[-ComputerName] <string>]  [<CommonParameters>]
    

ALIASES
    None
    

REMARKS
    Get-Help cannot find the Help files for this cmdlet on this computer. It is displaying only partial help.
        -- To download and install Help files for the module that includes this cmdlet, use Update-Help.
        -- To view the Help topic for this cmdlet online, type: "Get-Help Get-PendingUpdates -Online" or 
           go to https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PendingUpdates.md#get-pendingupdates.

```
## [Get-PrinterLog](docs/Get-PrinterLog.md)
```

examples      : @{example=System.Management.Automation.PSObject[]}
inputTypes    : 
alertSet      : @{alert=System.Management.Automation.PSObject[]}
syntax        : @{syntaxItem=@{name=Get-PrinterLog; parameter=System.Management.Automation.PSObject[]}}
parameters    : @{parameter=System.Management.Automation.PSObject[]}
details       : @{description=System.Management.Automation.PSObject[]; verb=Get; noun=PrinterLog; name=Get-PrinterLog}
description   : {@{Text=This function will return a log of all the printing that has occurred on a given print server.}}
relatedLinks  : @{navigationLink=@{uri=https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PrinterLog.md#get-printerlog; linkText=Online Version:}}
returnValues  : 
xmlns:maml    : http://schemas.microsoft.com/maml/2004/10
xmlns:command : http://schemas.microsoft.com/maml/dev/command/2004/10
xmlns:dev     : http://schemas.microsoft.com/maml/dev/2004/10
xmlns:MSHelp  : http://msdn.microsoft.com/mshelp
Name          : Get-PrinterLog
Category      : Function
Synopsis      : Get a log of all printing from a given server.
Component     : 
Role          : 
Functionality : 
ModuleName    : ComputerManagement

```
## [Get-PrinterLogs](docs/Get-PrinterLogs.md)
```
NAME
    Get-PrinterLogs
    
SYNTAX
    Get-PrinterLogs [[-LogName] <Object>] [-ComputerName] <Object>  [<CommonParameters>]
    

ALIASES
    None
    

REMARKS
    Get-Help cannot find the Help files for this cmdlet on this computer. It is displaying only partial help.
        -- To download and install Help files for the module that includes this cmdlet, use Update-Help.
        -- To view the Help topic for this cmdlet online, type: "Get-Help Get-PrinterLogs -Online" or 
           go to https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PrinterLogs.md#get-printerlogs.

```
## [Connect-Rdp](docs/Connect-Rdp.md)
```

examples      : @{example=System.Management.Automation.PSObject[]}
inputTypes    : 
alertSet      : @{alert=System.Management.Automation.PSObject[]}
syntax        : @{syntaxItem=@{name=Connect-Rdp; parameter=System.Management.Automation.PSObject[]}}
parameters    : @{parameter=System.Management.Automation.PSObject[]}
details       : @{description=System.Management.Automation.PSObject[]; verb=Connect; noun=Rdp; name=Connect-Rdp}
description   : {@{Text=To securely cache login credentials, you can use the command line utility cmdkey.exe. With this utility, you can save a username and a password for a given remote connection. Windows will then securely cache the information and automatically use 
                it when needed.}}
relatedLinks  : @{navigationLink=System.Management.Automation.PSObject[]}
returnValues  : 
xmlns:maml    : http://schemas.microsoft.com/maml/2004/10
xmlns:command : http://schemas.microsoft.com/maml/dev/command/2004/10
xmlns:dev     : http://schemas.microsoft.com/maml/dev/2004/10
xmlns:MSHelp  : http://msdn.microsoft.com/mshelp
Name          : Connect-Rdp
Category      : Function
Synopsis      : Connect to one or more computers over RDP
Component     : 
Role          : 
Functionality : 
ModuleName    : ComputerManagement

```
## [Get-RDPLoginEvent](docs/Get-RDPLoginEvent.md)
```

examples      : @{example=@{code=PS C:\> Get-RDPLoginEvents -Credentials $Credentials -ComputerName MyPC |Format-Table
                
                SourceNetworkAddress        Domain           TimeCreated                User
                --------------------        ------           -----------                ----
                192.168.1.1                 MyPC...          4/30/2011 8:20:02 AM       Administrator...
                192.168.1.1                 MyPC...          4/28/2011 4:53:01 PM       Administrator...
                192.168.1.1                 MyPC...          4/21/2011 2:01:42 PM       Administrator...
                192.168.1.1                 MyPC...          4/19/2011 11:42:59 AM      Administrator...
                192.168.1.1                 MyPC...          4/19/2011 10:30:52 AM      Administrator...; remarks=System.Management.Automation.PSObject[]; title=-------------------------- Example 1 --------------------------}}
inputTypes    : @{inputType=@{type=@{name=System.Object}; description=System.Management.Automation.PSObject[]}}
alertSet      : @{alert=System.Management.Automation.PSObject[]}
syntax        : @{syntaxItem=@{name=Get-RDPLoginEvent; parameter=System.Management.Automation.PSObject[]}}
parameters    : @{parameter=System.Management.Automation.PSObject[]}
details       : @{description=System.Management.Automation.PSObject[]; verb=Get; noun=RDPLoginEvent; name=Get-RDPLoginEvent}
description   : {@{Text=This function returns login attempts from the Microsoft Windows TerminalServices RemoteConnectionManager log. The specific events are logged as EventID 1149, and they are logged whether or not the user actually gets to the desktop.}}
relatedLinks  : @{navigationLink=@{uri=https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-RDPLoginEvent.md#Get-rdploginevent; linkText=Online Version:}}
returnValues  : @{returnValue=@{type=@{name=System.Object[]}; description=System.Management.Automation.PSObject[]}}
xmlns:maml    : http://schemas.microsoft.com/maml/2004/10
xmlns:command : http://schemas.microsoft.com/maml/dev/command/2004/10
xmlns:dev     : http://schemas.microsoft.com/maml/dev/2004/10
xmlns:MSHelp  : http://msdn.microsoft.com/mshelp
Name          : Get-RDPLoginEvent
Category      : Function
Synopsis      : Return Remote Desktop login attempts
Component     : 
Role          : 
Functionality : 
ModuleName    : ComputerManagement

```
## [Get-RDPLoginEvents](docs/Get-RDPLoginEvents.md)
```
NAME
    Get-RDPLoginEvents
    
SYNTAX
    Get-RDPLoginEvents [-ComputerName] <Object> [[-Credentials] <pscredential>]  [<CommonParameters>]
    

ALIASES
    None
    

REMARKS
    Get-Help cannot find the Help files for this cmdlet on this computer. It is displaying only partial help.
        -- To download and install Help files for the module that includes this cmdlet, use Update-Help.
        -- To view the Help topic for this cmdlet online, type: "Get-Help Get-RDPLoginEvents -Online" or 
           go to https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-RDPLoginEvents.md#Get-rdploginevents.

```
## [Grant-RegistryPermission](docs/Grant-RegistryPermission.md)
```

examples      : @{example=@{code=Grant-RegistryPermission -Path HKCU:\Environment\ -Principal DOMAIN\User01 -Rights FullControl
                
                Path                                    Owner               Access
                ----                                    -----               ------
                Microsoft.PowerShell.Core\Registry::...
                NT AUTHORITY\SYSTEM NT AUTHORITY\RESTRICTED Allow  ReadK...; remarks=System.Management.Automation.PSObject[]; title=-------------------------- EXAMPLE 1 --------------------------}}
inputTypes    : 
alertSet      : @{alert=System.Management.Automation.PSObject[]}
syntax        : @{syntaxItem=@{name=Grant-RegistryPermission; parameter=System.Management.Automation.PSObject[]}}
parameters    : @{parameter=System.Management.Automation.PSObject[]}
details       : @{description=System.Management.Automation.PSObject[]; verb=Grant; noun=RegistryPermission; name=Grant-RegistryPermission}
description   : {@{Text=This function allows you to set permissions on registry paths on a computer. Using the parameters you can specify the rights, inheritance and propagation of the rights.}}
relatedLinks  : @{navigationLink=System.Management.Automation.PSObject[]}
returnValues  : 
xmlns:maml    : http://schemas.microsoft.com/maml/2004/10
xmlns:command : http://schemas.microsoft.com/maml/dev/command/2004/10
xmlns:dev     : http://schemas.microsoft.com/maml/dev/2004/10
xmlns:MSHelp  : http://msdn.microsoft.com/mshelp
Name          : Grant-RegistryPermission
Category      : Function
Synopsis      : Grant permissions on registry paths
Component     : 
Role          : 
Functionality : 
ModuleName    : ComputerManagement

```
## [Get-ServiceTag](docs/Get-ServiceTag.md)
```

examples      : @{example=@{code=Get-ServiceTag -ComputerName Desktop-01
                
                SerialNumber
                ------------
                1AB2CD3; remarks=System.Management.Automation.PSObject[]; title=-------------------------- EXAMPLE 1 --------------------------}}
inputTypes    : 
alertSet      : @{alert=System.Management.Automation.PSObject[]}
syntax        : @{syntaxItem=@{name=Get-ServiceTag; parameter=@{Description=System.Management.Automation.PSObject[]; defaultValue=(& hostname); parameterValue=Object; name=ComputerName; type=@{name=Object; uri=}; required=false; variableLength=true; globbing=false; 
                pipelineInput=False; position=1; aliases=none}}}
parameters    : @{parameter=@{Description=System.Management.Automation.PSObject[]; defaultValue=(& hostname); parameterValue=Object; name=ComputerName; type=@{name=Object; uri=}; required=false; variableLength=true; globbing=false; pipelineInput=False; position=1; 
                aliases=none}}
details       : @{description=System.Management.Automation.PSObject[]; verb=Get; noun=ServiceTag; name=Get-ServiceTag}
description   : {@{Text=An example showing the only parameter.}}
relatedLinks  : @{navigationLink=@{uri=https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-ServiceTag.md#get-servicetag; linkText=Online Version:}}
returnValues  : 
xmlns:maml    : http://schemas.microsoft.com/maml/2004/10
xmlns:command : http://schemas.microsoft.com/maml/dev/command/2004/10
xmlns:dev     : http://schemas.microsoft.com/maml/dev/2004/10
xmlns:MSHelp  : http://msdn.microsoft.com/mshelp
Name          : Get-ServiceTag
Category      : Function
Synopsis      : Get the serial number (Dell ServiceTag) from Win32_BIOS
Component     : 
Role          : 
Functionality : 
ModuleName    : ComputerManagement

```
## [Set-ShutdownMethod](docs/Set-ShutdownMethod.md)
```
NAME
    Set-ShutdownMethod
    
SYNTAX
    Set-ShutdownMethod [-ComputerName] <string> [[-Credentials] <pscredential>] [[-ShutdownMethod] <int>] [-WhatIf] [-Confirm]  [<CommonParameters>]
    

ALIASES
    None
    

REMARKS
    Get-Help cannot find the Help files for this cmdlet on this computer. It is displaying only partial help.
        -- To download and install Help files for the module that includes this cmdlet, use Update-Help.
        -- To view the Help topic for this cmdlet online, type: "Get-Help Set-ShutdownMethod -Online" or 
           go to https://github.com/mod-posh/ComputerManagement/blob/master/docs/Set-ShutdownMethod.md#set-shutdownmethod.

```
## [Get-WinEventTail](docs/Get-WinEventTail.md)
```

examples      : @{example=@{code=Get-WinEventTail -LogName Application
                
                ProviderName: ESENT
                
                TimeCreated                     Id LevelDisplayName Message
                -----------                     -- ---------------- -------
                10/9/2014 11:55:51 AM          102 Information      svchost (7528) Instance: ...
                10/9/2014 11:55:51 AM          105 Information      svchost (7528) Instance: ...
                10/9/2014 11:55:51 AM          326 Information      svchost (7528) Instance: ...
                10/9/2014 12:05:49 PM          327 Information      svchost (7528) Instance: ...
                10/9/2014 12:05:49 PM          103 Information      svchost (7528) Instance: ...; remarks=System.Management.Automation.PSObject[]; title=-------------------------- EXAMPLE 1 --------------------------}}
inputTypes    : 
alertSet      : @{alert=System.Management.Automation.PSObject[]}
syntax        : @{syntaxItem=@{name=Get-WinEventTail; parameter=System.Management.Automation.PSObject[]}}
parameters    : @{parameter=System.Management.Automation.PSObject[]}
details       : @{description=System.Management.Automation.PSObject[]; verb=Get; noun=WinEventTail; name=Get-WinEventTail}
description   : {@{Text=This function will allow you to tail Windows Event Logs. You specify a Logname for either the original logs, Application, System and Security or the new format for the newer logs Microsoft-Windows-PowerShell/Operational}}
relatedLinks  : @{navigationLink=System.Management.Automation.PSObject[]}
returnValues  : 
xmlns:maml    : http://schemas.microsoft.com/maml/2004/10
xmlns:command : http://schemas.microsoft.com/maml/dev/command/2004/10
xmlns:dev     : http://schemas.microsoft.com/maml/dev/2004/10
xmlns:MSHelp  : http://msdn.microsoft.com/mshelp
Name          : Get-WinEventTail
Category      : Function
Synopsis      : A tail cmdlet for Eventlogs
Component     : 
Role          : 
Functionality : 
ModuleName    : ComputerManagement

```


