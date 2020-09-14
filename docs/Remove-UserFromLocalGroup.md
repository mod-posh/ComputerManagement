---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Remove-UserFromLocalGroup
schema: 2.0.0
---

# Remove-UserFromLocalGroup

## SYNOPSIS
Removes a user/group from a local computer group.

## SYNTAX

```
Remove-UserFromLocalGroup [-ComputerName] <String> [-UserName] <String> [-GroupName] <String> [-WhatIf]
 [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Removes a user/group from a local computer group.

## EXAMPLES

### EXAMPLE 1
```
Remove-UserFromLocalGroup -ComputerName MyComputer -UserName RandomUser
```

Description
         -----------
         This example removes a user from the local administrators group.

### EXAMPLE 2
```
Remove-UserFromLocalGroup -ComputerName MyComputer -UserName RandomUser -GroupName Users
```

Description
-----------
This example removes a user from the local users group.

## PARAMETERS

### -ComputerName
{{ Fill ComputerName Description }}

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

### -GroupName
Name of the group where that the user/group is a member of.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserName
{{ Fill UserName Description }}

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

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
You will need to run this with either UAC disabled or from an elevated prompt.

## RELATED LINKS

[https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Remove-UserFromLocalGroup](https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Remove-UserFromLocalGroup)

