---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-NetShare#get-netshare
schema: 2.0.0
---

# Get-NetShare

## SYNOPSIS
Return a list of shares without using WMI

## SYNTAX

```
Get-NetShare [-ComputerName] <String> [-Type] <String> [<CommonParameters>]
```

## DESCRIPTION
This function returns a list of shares using the old net view command. This
works well in situations where a fierwall may be blocking access.

## EXAMPLES

### EXAMPLE 1
```
Get-NetShare -ComputerName server-01 -Type Print

Server      Share   Path
------      -----   ----
server-01   hp01    \\\\server-01\hp01
server-01   hp02    \\\\server-01\hp02
server-01   hp03    \\\\server-01\hp03
```

This example shows the basic usage for this function

## PARAMETERS

### -ComputerName
The name of the server that has file or print shares

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Type
This will be either Print or Disk
    Print returns printer shares
    Disk returns file shares

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
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
FunctionName : Get-NetShares
Created by   : jspatton
Date Coded   : 10/08/2014 11:08:30

## RELATED LINKS

