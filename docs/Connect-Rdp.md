---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Connect-Rdp#connect-rdp
schema: 2.0.0
---

# Connect-Rdp

## SYNOPSIS
Connect to one or more computers over RDP

## SYNTAX

```
Connect-Rdp [-ComputerName] <Object> [[-Credential] <PSCredential>] [<CommonParameters>]
```

## DESCRIPTION
To securely cache login credentials, you can use the command line utility
cmdkey.exe.
With this utility, you can save a username and a password for
a given remote connection.
Windows will then securely cache the information
and automatically use it when needed.

## EXAMPLES

### EXAMPLE 1
```
Connect-Rdp -ComputerName Server-01 -Credential Company.com\Administrator
```

The basic syntax showing a connection to a single machine

### EXAMPLE 2
```
Connect-Rdp -ComputerName Server-01, 192.168.1.2, server-03.company.com -Credential COMPANY\Administrator
```

This example shows connecting to multiple servers at once.

### EXAMPLE 3
```
"server-04","server-06" |Connect-Rdp -Credential $Credentials
```

This example shows passing the computernames over the pipe

## PARAMETERS

### -ComputerName
The hostname or IP address of the computer to connect to

```yaml
Type: System.Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Credential
A credential object that contains a valid username and password for
the remote computer

```yaml
Type: System.Management.Automation.PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
FunctionName : Connect-RDP
Created by   : jspatton
Date Coded   : 06/23/2014 08:48:25

## RELATED LINKS

[Automatic Remote Desktop onnection](http://www.powershellmagazine.com/2014/04/18/automatic-remote-desktop-connection/)

