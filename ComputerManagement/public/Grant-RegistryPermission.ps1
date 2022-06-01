Function Grant-RegistryPermission {
 [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Grant-RegistryPermission.md#grant-registrypermission')]
 Param
 (
  [Parameter(Mandatory = $true)]
  [string] $Path,
  [Parameter(Mandatory = $true)]
  [string] $Principal,
  [Parameter(Mandatory = $true)]
  [Security.AccessControl.RegistryRights] $Rights,
  [Security.AccessControl.InheritanceFlags] $Inheritance = [Security.AccessControl.InheritanceFlags]::None,
  [Security.AccessControl.PropagationFlags] $Propagation = [Security.AccessControl.PropagationFlags]::None
 )
 Begin {
  $Identity = new-object System.Security.Principal.NTAccount($Principal)
  $IdentityReference = $Identity.Translate([System.Security.Principal.SecurityIdentifier])
 }
 Process {
  $RegistryAccessRule = New-Object Security.AccessControl.RegistryAccessRule $IdentityReference, $Rights, $Inheritance, $Propagation, Allow
  $Acl = Get-Acl $Path
  $Acl.AddAccessRule($RegistryAccessRule)
  Set-Acl -Path $Path -AclObject $Acl
 }
 End {
  Get-Acl $Path
 }
}