---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Export-EventLog.md#export-eventlog
schema: 2.0.0
---

# Export-EventLog

## SYNOPSIS
Export an Eventlog from a local or remote computer

## SYNTAX

```
Export-EventLog [[-ComputerName] <Object>] [[-Credential] <PSCredential>] [-ListLog] [[-LogName] <Object>]
 [[-Destination] <Object>] [<CommonParameters>]
```

## DESCRIPTION
This function will export the logname you specify to the folder
and filename that you provide.
The exported file is in the native
format for Event logs.

This function leverages the System.Diagnostics.Eventing.Reader class
to export the log of the local or remote computer.

## EXAMPLES

### EXAMPLE 1
```
Export-EventLogs -ComputerName sql -Credential (Get-Credential) -LogName Application -Destination 'C:\LogFiles1\Application.evtx'
```

This example shows how to export the Application log from a computer named SQL
and save the file as Application.evtx in a folder called LogFiles. This also
shows how to use the Get-Credential cmdlet to pass credentials into the function.

### EXAMPLE 2
```
Export-EventLog -ListLog
Application
HardwareEvents
Internet Explorer
Key Management Service
Media Center
```

This example shows how to list the lognames on the local computer

### EXAMPLE 3
```
Export-EventLog -LogName Application -Destination C:\Logs\App.evtxExport-EventLog -LogName Application -Destination C:\Logs\App.evtx
```

This example shows how to export the Application log on the local computer to
a folder on the local computer.

## PARAMETERS

### -ComputerName
Type the NetBIOS name, an Internet Protocol (IP) address, or the fully
qualified domain name of the computer.
The default value is the local
computer.

This parameter accepts only one computer name at a time.
To find event logs
or events on multiple computers, use a ForEach statement.

To get events and event logs from remote computers, the firewall port for
the event log service must be configured to allow remote access.

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
Specifies a user account that has permission to perform this action.
The
default value is the current user.

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

### -Destination
The full path and filename to where the log should be exported to.

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ListLog
If present the function will list all the logs currently available on the
computer.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -LogName
Export messages from the specified LogName

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: False
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
FunctionName : Export-EventLogs
Created by   : jspatton
Date Coded   : 04/30/2012 12:36:12

The folder and filename that you specify will be created on the remote machine.

## RELATED LINKS
