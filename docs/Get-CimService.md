---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/get-cimservice.md#get-cimservice
schema: 2.0.0
---

# Get-CimService

## SYNOPSIS
Get a list of services

## SYNTAX

```
Get-CimService [[-Computer] <String>] [[-Credential] <PSCredential>] [[-State] <String>]
 [[-StartMode] <String>] [<CommonParameters>]
```

## DESCRIPTION
This function returns a list of services on a given computer. This list can be
filtered based on the given StartMode  (ie. Running, Stopped) as well as
filtered on StartMode (ie. Auto, Manual).

## EXAMPLES

### EXAMPLE 1
```
Get-CimService |Format-Table -AutoSize

ExitCode Name                 ProcessId StartMode State   Status
-------- ----                 --------- --------- -----   ------
		0 atashost                  1380 Auto      Running OK
		0 AudioEndpointBuilder       920 Auto      Running OK
		0 AudioSrv                   880 Auto      Running OK
		0 BFE                       1236 Auto      Running OK
		0 BITS                       964 Auto      Running OK
		0 CcmExec                   2308 Auto      Running OK
		0 CryptSvc                  1088 Auto      Running OK
```

Description
-----------
This example shows the default options in place

### EXAMPLE 2
```
Get-CimService -State "stopped" |Format-Table -AutoSize

ExitCode Name                           ProcessId StartMode State   Status
-------- ----                           --------- --------- -----   ------
		0 AppHostSvc                             0 Auto      Stopped OK
		0 clr_optimization_v4.0.30319_32         0 Auto      Stopped OK
		0 clr_optimization_v4.0.30319_64         0 Auto      Stopped OK
		0 MMCSS                                  0 Auto      Stopped OK
		0 Net Driver HPZ12                       0 Auto      Stopped OK
		0 Pml Driver HPZ12                       0 Auto      Stopped OK
		0 sppsvc                                 0 Auto      Stopped OK
```

Description
-----------
This example shows the output when specifying the state parameter

### EXAMPLE 3
```
Get-CimService -State "stopped" -StartMode "disabled" |Format-Table -AutoSize

ExitCode Name                           ProcessId StartMode State   Status
-------- ----                           --------- --------- -----   ------
	1077 clr_optimization_v2.0.50727_32         0 Disabled  Stopped OK
	1077 clr_optimization_v2.0.50727_64         0 Disabled  Stopped OK
	1077 CscService                             0 Disabled  Stopped OK
	1077 Mcx2Svc                                0 Disabled  Stopped OK
	1077 MSSQLServerADHelper100                 0 Disabled  Stopped OK
	1077 NetMsmqActivator                       0 Disabled  Stopped OK
	1077 NetPipeActivator                       0 Disabled  Stopped OK
```

Description
-----------
This example shows how to specify a different state and startmode.

### EXAMPLE 4
```
Get-CimService -Computer dpm -Credential "Domain\Administrator" |Format-Table -AutoSize

ExitCode Name                   ProcessId StartMode State   Status
-------- ----                   --------- --------- -----   ------
		0 AppHostSvc                  1152 Auto      Running OK
		0 BFE                          564 Auto      Running OK
		0 CryptSvc                    1016 Auto      Running OK
		0 DcomLaunch                   600 Auto      Running OK
		0 Dhcp                         776 Auto      Running OK
		0 Dnscache                    1016 Auto      Running OK
		0 DPMAMService                1184 Auto      Running OK
```

Description
-----------
This example shows how to specify a remote computer and credentials to authenticate with.

## PARAMETERS

### -Computer
The NetBIOS name of the computer to retrieve services from

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: (& hostname)
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
The DOMAIN\USERNAME of an account with permissions to access services.

```yaml
Type: System.Management.Automation.PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -StartMode
Most often this will be either Auto or Manual, but possible values include
	Auto
	Manual
	Disabled

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: Auto
Accept pipeline input: False
Accept wildcard characters: False
```

### -State
Most often this will be either Running or Stopped, but possible values include
	Running
	Stopped
	Paused

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: Running
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
Depending on how you are setup you may need to provide credentials in order to access remote machines
You may need to have UAC disabled or run PowerShell as an administrator to see services locally

## RELATED LINKS

