---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/New-Password.md#new-password
schema: 2.0.0
---

# New-Password

## SYNOPSIS
Create a new password

## SYNTAX

```
New-Password [[-Length] <Int32>] [[-Count] <Int32>] [-Strong] [-asSecureString] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION
This function creates a password using the cryptographic Random Number Generator
see the MSDN link for more details.

## EXAMPLES

### Example 1
```powershell
PS C:\> New-Password -Length 64 -Count 5 -Strong

Password
--------
UkQfV)RHwcQ3a)s8Z#QwSCLxlI*y28kEPmcQUVM2HrACf@PxRJDLk4ffge#1m_8j
XfAwZOh_lrzLE8NwkSTPs5#LNkW4uZ0Wm_ST5UzERqhY45)HBpN$_@@MxDeLiosW
h(BN(y^Gip&pU$KJpAAajgopQyoSbCn41m53mc__wV@q$DY5a$iN&O0fnf9hvO1&
tXkFwY_pe(VIFf$R2^bKyKy)D_H6q^Nz7MgSDylXrV2GIkyiFVnvfbd9KENFuHQz
&6LPlWRB$#yqD@!IEuJ9JcMTKrsA_t(AbWRGTLx@2Fw__j08n(TGi6wgPE6XlLWg
```

This example creates 5 strong passwords that are 64 characters long

## PARAMETERS

### -asSecureString
Returns passwords as SecureStrings

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Count
An integer that defines how many passwords to create

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Length
An integer that defines how long the password should be

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Strong
A switch that if present will include special characters

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
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

### None
## OUTPUTS

### System.Object[]
## NOTES

## RELATED LINKS

[PowerShell Password Generator](http://www.peterprovost.org/blog/2007/06/22/Quick-n-Dirty-PowerShell-Password-Generator/)
[MSDN RNG Crypto Service Provider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider.aspx)