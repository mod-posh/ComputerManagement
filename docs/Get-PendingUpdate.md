---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PendingUpdate.md#get-pendingupdate
schema: 2.0.0
---

# Get-PendingUpdate

## SYNOPSIS
Retrieves the updates waiting to be installed from WSUS

## SYNTAX

```
Get-PendingUpdate [[-ComputerName] <String>] [<CommonParameters>]
```

## DESCRIPTION
Retrieves the updates that are available to install on the local system

## EXAMPLES

### EXAMPLE 1
```
Get-PendingUpdates
```

## PARAMETERS

### -ComputerName
Computer or computers to find updates for.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
Author: Boe Prox
Date Created: 05Mar2011
RPC Dynamic Ports need to be enabled on inbound remote servers.

## RELATED LINKS
