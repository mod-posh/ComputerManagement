---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-MappedDrive.md#get-mappeddrive
schema: 2.0.0
---

# Get-MappedDrive

## SYNOPSIS
Return a list of mapped network drives on the computer

## SYNTAX

```
Get-MappedDrive [[-ComputerName] <String>] [[-Credentials] <PSCredential>] [<CommonParameters>]
```

## DESCRIPTION
This function returns a list of mapped network drives from the
local or remote computer.

## EXAMPLES

### EXAMPLE 1
```
Get-MappedDrives

Caption      : V:
FreeSpace    : 4129467170816
Name         : V:
ProviderName : \\\\users2.company.com\homedir4\jspatton
Size         : 10737418240
VolumeName   : 236
```

This is the basic syntax of the command.

### EXAMPLE 2
```
Get-MappedDrives -ComputerName Desktop-PC01

Caption      : U:
FreeSpace    : 134377222144
Name         : U:
ProviderName : \\\\people.company.com\i\jspatton
Size         : 687194767360
VolumeName   : IGroup
```

This syntax shows passing the optional ComputerName parameter.
If this is
not the local computer and you didn't pass the Credentials object, you
will be prompted.

## PARAMETERS

### -ComputerName
The name of the computer to get the list from.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: (hostname)
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credentials
A credentials object to pass if needed.

```yaml
Type: PSCredential
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
FunctionName : Get-MappedDrives
Created by   : jspatton
Date Coded   : 03/20/2012 16:03:52

## RELATED LINKS
