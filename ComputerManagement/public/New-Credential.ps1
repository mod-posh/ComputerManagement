function New-Credential {
 [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/New-Credential.md#new-credential',
  SupportsShouldProcess,
  ConfirmImpact = 'Low')]
 Param
 (
  [Parameter(Mandatory = $true)]
  [string]$Username,
  [Parameter(Mandatory = $true)]
  $Password
 )
 begin {

 }
 process {
  if ($PSCmdlet.ShouldProcess("New", "New Credential")) {
   switch ($Password.GetType().Name.ToLower()) {
    'securestring' {
     Write-Verbose "Found SecureString Password";
     New-Object System.Management.Automation.PSCredential ($Username, $Password);
    }
    'string' {
     Write-Verbose "Found String Password"
     $SecureString = [System.Security.SecureString]::New();
     $Password.ToCharArray() | Foreach-Object { $SecureString.AppendChar($_) };
     New-Object System.Management.Automation.PSCredential ($Username, $SecureString);
    }
   }
  }
 }
 end {

 }
}