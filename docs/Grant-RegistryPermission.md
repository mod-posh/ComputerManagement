---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Grant-RegistryPermission
schema: 2.0.0
---

# Grant-RegistryPermission

## SYNOPSIS
Grant permissions on registry paths

## SYNTAX

```
Grant-RegistryPermission [-Path] <String> [-Principal] <String> [-Rights] <RegistryRights>
 [[-Inheritance] <InheritanceFlags>] [[-Propagation] <PropagationFlags>] [<CommonParameters>]
```

## DESCRIPTION
This function allows you to set permissions on registry paths on a computer.
Using
the parameters you can specify the rights, inheritance and propagation of the rights.

## EXAMPLES

### EXAMPLE 1
```
Grant-RegistryPermission -Path HKCU:\Environment\ -Principal DOMAIN\User01 -Rights FullControl
```

Path                                    Owner               Access
----                                    -----               ------
Microsoft.PowerShell.Core\Registry::...
NT AUTHORITY\SYSTEM NT AUTHORITY\RESTRICTED Allow  ReadK...

Description
-----------
This example grants full control to the environment key for user01

## PARAMETERS

### -Inheritance
Inheritance flags specify the semantics of inheritance for access control entries (ACEs).
See
http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.inheritanceflags(v=vs.110).aspx

```yaml
Type: System.Security.AccessControl.InheritanceFlags
Parameter Sets: (All)
Aliases:
Accepted values: None, ContainerInherit, ObjectInherit

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Path
A registry path

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

### -Principal
Username in DOMAIN\User format

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

### -Propagation
Specifies how Access Control Entries (ACEs) are propagated to child objects.
These flags are significant
only if inheritance flags are present.
See
http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.propagationflags(v=vs.110).aspx

```yaml
Type: System.Security.AccessControl.PropagationFlags
Parameter Sets: (All)
Aliases:
Accepted values: None, NoPropagateInherit, InheritOnly

Required: False
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Rights
Specifies the access control rights that can be applied to registry objects.
See
http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights(v=vs.110).aspx

```yaml
Type: System.Security.AccessControl.RegistryRights
Parameter Sets: (All)
Aliases:
Accepted values: QueryValues, SetValue, CreateSubKey, EnumerateSubKeys, Notify, CreateLink, Delete, ReadPermissions, WriteKey, ExecuteKey, ReadKey, ChangePermissions, TakeOwnership, FullControl

Required: True
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
FunctionName : Grant-RegistryPermission
Created by   : jspatton
Date Coded   : 01/12/2015 14:53:41

I lifted this almost completely from iheartpowershell's blog, this appears to be the first
iteration of this function, I have since found it copied verbatim onto other blogs, so I feel
the need to give credit where credit is due.

I modified this function to build the identity from a username, and pass in the identityrefernce
object to the rule.

## RELATED LINKS

[https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Grant-RegistryPermission](https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#Grant-RegistryPermission)

[http://www.iheartpowershell.com/2011/09/grant-registry-permissions.html](http://www.iheartpowershell.com/2011/09/grant-registry-permissions.html)

[http://msdn.microsoft.com/en-us/library/ms147899(v=vs.110).aspx](http://msdn.microsoft.com/en-us/library/ms147899(v=vs.110).aspx)

[http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights(v=vs.110).aspx](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights(v=vs.110).aspx)

[http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.inheritanceflags(v=vs.110).aspx](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.inheritanceflags(v=vs.110).aspx)

[http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.propagationflags(v=vs.110).aspx](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.propagationflags(v=vs.110).aspx)

