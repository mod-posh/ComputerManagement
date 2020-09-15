---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-InvalidLogonAttempt.md#get-invalidlogonattempt
schema: 2.0.0
---

# Get-InvalidLogonAttempt

## SYNOPSIS
Return a list of invalid logon attempts.

## SYNTAX

```
Get-InvalidLogonAttempts [-ComputerName] <Object> [[-LogName] <Object>] [[-EventID] <Object>]
 [<CommonParameters>]
```

## DESCRIPTION
This function queries the security log of a given computer and
retrieves Event ID 4625, failed logon attempt.

## EXAMPLES

### EXAMPLE 1
```
Get-InvalidLogonAttempts -ComputerName Desktop-pc1 -LogName 'Security' -EventID 4625

Message        MachineName    TimeCreated   IpAddress         LogonType TargetUserName IpPort
-------        -----------    -----------   ---------         --------- -------------- ------
An account ... Desktop-pc1... 10/26/2011... ##.###.###...            10 Daniel         62581
An account ... Desktop-pc1... 10/26/2011... ##.###.###...            10 Daniel         11369
An account ... Desktop-pc1... 10/26/2011... ##.###.###...            10 Daniel         47575
An account ... Desktop-pc1... 10/26/2011... ##.###.###...            10 Daniel         51144
```

This is the basic syntax of the command, the output is returned to stdin.

### EXAMPLE 2
```
Get-InvalidLogonAttempts |Export-Csv -Path .\InvalidLoginAttempts.csv
```

This example shows redirecting the output through the Export-CSV command to get
a csv file.

## PARAMETERS

### -ComputerName
The name of the computer to pull logs from

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -EventID
The Event ID to return.

You will notice that I have set the EventID to 4625, since
this particular script was designed to find those particular
entries.
This can be modified to suit your needs.

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: 4625
Accept pipeline input: False
Accept wildcard characters: False
```

### -LogName
The name of the Event Log.

You will notice that I have set the LogName to Security, since
this particular script was designed to find a specific entry.
This can be modified to suit your needs.

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: Security
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
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

If you adjust the script to look for event id's other than 4625, you will
want to examine the Event Properties.
This is similar to viewing the
"Friendly" view of an event in the event log.
Below are all the properties
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

## RELATED LINKS
