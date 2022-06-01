Function Get-NetShare {
 [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-NetShare.md#get-netshare')]
 Param
 (
  [parameter(Mandatory = $true)]
  [string]$ComputerName,
  [ValidateSet("Print", "Disk", IgnoreCase = $true)]
  [parameter(Mandatory = $true)]
  [string]$Type
 )
 Begin {
  Write-Verbose "Getting share from server"
  $List = net view "\\$($ComputerName)" | Select-String $Type
  Write-Verbose "$($List)"
 }
 Process {
  foreach ($Entry in $List) {
   Write-Verbose "Converting regex to string"
   $Line = $Entry.ToString();
   Write-Debug $Line
   Write-Verbose "Building share property"
   $Share = $Line.Substring(0, $Line.IndexOf($Type)).trim()
   Write-Verbose "Building Description property"
   $Description = $Line.Substring($Line.IndexOf($Type), $Line.Length - $Line.IndexOf($Type)).Replace($Type, "").Trim()
   $Path = "\\$($ComputerName)\$($Share)"
   New-Object -TypeName psobject -Property @{
    Server      = $ComputerName
    Share       = $Share
    Description = $Description
    Path        = $Path
   } | Select-Object -Property Server, Share, Description, Path
  }
 }
 End {
 }
}