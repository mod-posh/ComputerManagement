---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Set-ShutdownMethod.md#set-shutdownmethod
schema: 2.0.0
---

# Set-ShutdownMethod

## SYNOPSIS
Execute the Win32Shutdown method on a remote computer

## SYNTAX

```
Set-ShutdownMethod [-ComputerName] <String> [[-Credentials] <PSCredential>] [[-ShutdownMethod] <Int32>]
 [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
This function executes the Win32Shutdown method on a remote computer. This can
be either an IP, NetBIOS name or FQDN. Use the ShutdownMethod param to specify
the type of shutdown.

## EXAMPLES

### Example 1
```powershell
PS C:\> Set-ShutdownMethod -ComputerName Desktop-pc01
```

This is the default syntax for this command

### Example 2
```powershell
PS C:\> Set-ShutdownMethod -ComputerName Desktop-pc01 -ShutdownMethod 0
```

This shows how to use the optional parameter ShutdownMethod

## PARAMETERS

### -ComputerName
The IP, NetBIOS or FQDN of the remote computer.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Credentials
A user account with the ability to retreive these events.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ShutdownMethod
Win32Shutdown accepts one of the following in32's
 0 = Logoff (Default)
 1 = Shutdown
 2 = Reboot
 4 = Force Logoff (Doesn't work)
 8 = PowerOff

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
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
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

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

### System.String
## OUTPUTS

### System.String
## NOTES
You will need proper credentials on the remote machine for this to work.

## RELATED LINKS
