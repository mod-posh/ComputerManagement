---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Remove-UserFromLocalGroup
schema: 2.0.0
---

# Set-Pass

## SYNOPSIS
Change the password of an existing user account.

## SYNTAX

```
Set-Pass [-ComputerName] <String> [-UserName] <String> [-Password] <SecureString> [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION
This function will change the password for an existing user account.

## EXAMPLES

### Example 1
```powershell
PS C:\> Set-Pass -ComputerName MyComputer -UserName MyUserAccount -Password N3wP@ssw0rd
```

This shows using the function against a remote computer

## PARAMETERS

### -ComputerName
The NetBIOS name of the computer that you will add the account to.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Password
The password for the account, this must follow password policies enforced on the
destination computer.

```yaml
Type: System.Security.SecureString
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserName
The user name of the account that will be created.

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

### None

## OUTPUTS

### System.String

## NOTES
You will need to run this with either UAC disabled or from an elevated prompt.
## RELATED LINKS
