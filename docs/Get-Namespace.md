---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-Namespace.md#get-namespace
schema: 2.0.0
---

# Get-Namespace

## SYNOPSIS
Return a collection of classes from a namespace

## SYNTAX

```
Get-Namespace [-Namespace] <String> [-ComputerName] <String> [<CommonParameters>]
```

## DESCRIPTION
This function will return a collection of classes from the provided namespace.
This method uses SWbemLocator to connect to a computer, the resulting
SWbemServices object is used to return the SubclassesOf() the given namespace.

## EXAMPLES

### EXAMPLE 1
```
Get-Namespace -Namespace 'root\ccm' -ComputerName 'sccm'

Path            : \\\\SCCM\ROOT\ccm:__NAMESPACE
RelPath         : __NAMESPACE
Server          : SCCM
Namespace       : ROOT\ccm
ParentNamespace : ROOT
DisplayName     : WINMGMTS:{authenticationLevel=pkt,impersonationLevel=impersonate}!\\\\SCCM\ROOT\ccm:__NAMESPACE
Class           : __NAMESPACE
IsClass         : True
IsSingleton     : False
Keys            : System.__ComObject
Security_       : System.__ComObject
Locale          :
Authority       :
```

A simple example showing usage and output of the command.

### EXAMPLE 2
```
Get-Namespace -Namespace $NameSpace -ComputerName $ComputerName |Select-Object -Property Class

Class
-----
__SystemClass
__thisNAMESPACE
__NAMESPACE
__Provider
__Win32Provider
__ProviderRegistration
__EventProviderRegistration
__EventConsumerProviderRegistration
```

This example shows piping the output of the Get-Namespace function to Select-Object to return
one of the properties of a class.

## PARAMETERS

### -ComputerName
The computer to connect to

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

### -Namespace
The WMI namespace to enumerate

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
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
FunctionName : Get-Namespace
Created by   : jspatton
Date Coded   : 05/21/2012 12:50:50

## RELATED LINKS


