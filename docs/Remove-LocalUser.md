---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Remove-LocalUser.md#remove-localuser
schema: 2.0.0
---

# Remove-LocalUser

## SYNOPSIS
Delete a user account from the local computer.

## SYNTAX

```
Remove-LocalUser [-ComputerName] <Object> [-UserName] <Object> [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Basic syntax of the command.

## EXAMPLES

### EXAMPLE 1
```
Remove-LocalUser -ComputerName Desktop -UserName TestAcct
```

## PARAMETERS

### -ComputerName
The NetBIOS name of the computer the account is found on

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserName
The username to delete

```yaml
Type: Object
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
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs. The cmdlet is not run.

```yaml
Type: SwitchParameter
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
The user context the script is run under must be able to delete accounts on the remote computer

## RELATED LINKS
