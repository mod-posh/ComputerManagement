---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-OpenSessions.md#get-opensessions
schema: 2.0.0
---

# Get-OpenSessions

## SYNOPSIS
Return a list of open sessions

## SYNTAX

```
Get-OpenSessions [[-ComputerName] <Object>] [<CommonParameters>]
```

## DESCRIPTION
This function returns a list of open session on a given server.
The output is
similar to that of the Manage Open Sessions dialog in the Share and Storage
Management console.

## EXAMPLES

### EXAMPLE 1
```
Get-OpenSessions -ComputerName fs

User          Computer         ConnectTime     IdleTime
----          --------         -----------     --------
user1         10.10.1.62              1615            1
user2         10.10.1.156             7529           17
```

This example shows the basic usage of the command.

## PARAMETERS

### -ComputerName
This is the FQDN or NetBIOS name of the computer

```yaml
Type: System.Object
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: (hostname)
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
FunctionName : Get-OpenSessions
Created by   : Jeff Patton
Date Coded   : 09/26/2011 11:35:40

## RELATED LINKS

