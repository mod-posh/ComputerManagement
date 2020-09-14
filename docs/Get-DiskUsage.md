---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-DiskUsage.md#get-diskusage
schema: 2.0.0
---

# Get-DiskUsage

## SYNOPSIS
Get the disk usage of a given path

## SYNTAX

```
Get-DiskUsage [[-Path] <String>] [<CommonParameters>]
```

## DESCRIPTION
This function returns the disk usage of a given path

## EXAMPLES

### EXAMPLE 1
```
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
```

This shows the basic syntax of the command

### EXAMPLE 2
```
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
```

This example shows piping the output through Sort-Object

## PARAMETERS

### -Path
The path to check

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: .
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
FunctionName : Get-DiskUsage
Created by   : jspatton
Date Coded   : 03/21/2012 10:29:24

If you don't have access to read the contents of a given folder
the function returns 0.

## RELATED LINKS
