---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-ServiceTag.md#get-servicetag
schema: 2.0.0
---

# Get-ServiceTag

## SYNOPSIS
Get the serial number (Dell ServiceTag) from Win32_BIOS

## SYNTAX

```
Get-ServiceTag [[-ComputerName] <Object>] [<CommonParameters>]
```

## DESCRIPTION
An example showing the only parameter.

## EXAMPLES

### EXAMPLE 1
```
Get-ServiceTag -ComputerName Desktop-01

SerialNumber
------------
1AB2CD3
```

## PARAMETERS

### -ComputerName
The NetBIOS name of the computer.

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: (& hostname)
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
This space intentionally left blank.

## RELATED LINKS
