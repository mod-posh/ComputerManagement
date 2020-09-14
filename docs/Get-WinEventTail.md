---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-WinEventTail.md#get-wineventtail
schema: 2.0.0
---

# Get-WinEventTail

## SYNOPSIS
A tail cmdlet for Eventlogs

## SYNTAX

```
Get-WinEventTail [[-LogName] <String>] [[-ShowExisting] <Int32>] [<CommonParameters>]
```

## DESCRIPTION
This function will allow you to tail Windows Event Logs. You specify a Logname
for either the original logs, Application, System and Security or the new format
for the newer logs Microsoft-Windows-PowerShell/Operational

## EXAMPLES

### EXAMPLE 1
```
Get-WinEventTail -LogName Application

ProviderName: ESENT

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
10/9/2014 11:55:51 AM          102 Information      svchost (7528) Instance: ...
10/9/2014 11:55:51 AM          105 Information      svchost (7528) Instance: ...
10/9/2014 11:55:51 AM          326 Information      svchost (7528) Instance: ...
10/9/2014 12:05:49 PM          327 Information      svchost (7528) Instance: ...
10/9/2014 12:05:49 PM          103 Information      svchost (7528) Instance: ...
```

## PARAMETERS

### -LogName
Specify a valid Windows Eventlog name

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: System
Accept pipeline input: False
Accept wildcard characters: False
```

### -ShowExisting
An integer to show the number of events to start with, the default is 10

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: 10
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
FunctionName : Get-WinEventTail
Created by   : jspatton
Date Coded   : 10/09/2014 13:20:22

## RELATED LINKS

[StackOverflow Question](http://stackoverflow.com/questions/15262196/powershell-tail-windows-event-log-is-it-possible)

