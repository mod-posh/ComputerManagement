---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-RDPLoginEvent.md#Get-rdploginevent
schema: 2.0.0
---

# Get-RDPLoginEvent

## SYNOPSIS
Return Remote Desktop login attempts

## SYNTAX

```
Get-RDPLoginEvent [-ComputerName] <Object> [[-Credentials] <PSCredential>] [<CommonParameters>]
```

## DESCRIPTION
This function returns login attempts from the Microsoft Windows TerminalServices
RemoteConnectionManager log. The specific events are logged as EventID 1149, and
they are logged whether or not the user actually gets to the desktop.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-RDPLoginEvents -Credentials $Credentials -ComputerName MyPC |Format-Table

SourceNetworkAddress        Domain           TimeCreated                User
--------------------        ------           -----------                ----
192.168.1.1                 MyPC...          4/30/2011 8:20:02 AM       Administrator...
192.168.1.1                 MyPC...          4/28/2011 4:53:01 PM       Administrator...
192.168.1.1                 MyPC...          4/21/2011 2:01:42 PM       Administrator...
192.168.1.1                 MyPC...          4/19/2011 11:42:59 AM      Administrator...
192.168.1.1                 MyPC...          4/19/2011 10:30:52 AM      Administrator...
```

This example shows piping the output to Format-Table

## PARAMETERS

### -ComputerName
This is the NetBIOS name of the computer to pull events from.

```yaml
Type: System.Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Credentials
A user account with the ability to retreive these events.

```yaml
Type: System.Management.Automation.PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.Object
## OUTPUTS

### System.Object[]
## NOTES
The Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational needs
to be enabled The user account supplied in $Credentials needs to have permission
to view this log No output is returned if the log is empty.

## RELATED LINKS
