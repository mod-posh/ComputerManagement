---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Remove-LocalUser#remove-localuser
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
This function will delete a user account from the local computer

## EXAMPLES

### EXAMPLE 1
```
Remove-LocalUser -ComputerName Desktop -UserName TestAcct
```

Description
-----------
Basic syntax of the command.

## PARAMETERS

### -ComputerName
The NetBIOS name of the computer the account is found on

```yaml
Type: System.Object
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
Type: System.Object
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
Shows what would happen if the cmdlet runs. The cmdlet is not run.

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
The user context the script is run under must be able to delete accounts on the remote computer

## RELATED LINKS

