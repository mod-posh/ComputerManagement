---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Get-OpenFiles
schema: 2.0.0
---

# Get-OpenFiles

## SYNOPSIS
Get a list of files open on the server

## SYNTAX

```
Get-OpenFiles [[-ComputerName] <Object>] [<CommonParameters>]
```

## DESCRIPTION
This function returns a list of files open on a given server.
The output is
similar to that of the Manage Open Files from the Share and Storage Management
console.

## EXAMPLES

### EXAMPLE 1
```
Get-OpenFiles -ComputerName fs
```

User          Path                              LockCount
----          ----                              ---------
User1         F:\Users\User1\Documents\Data\... 
0
User2         P:\Public                                 0

Description
-----------
This example shows the basic usage of this command.

## PARAMETERS

### -ComputerName
The NetBIOS or FQDN of the computer

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
FunctionName : Get-OpenFiles
Created by   : Jeff Patton
Date Coded   : 09/26/2011 13:01:38

## RELATED LINKS

[https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Get-OpenFiles](https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Get-OpenFiles)

