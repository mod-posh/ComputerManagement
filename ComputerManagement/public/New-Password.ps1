Function New-Password {
 [OutputType([System.Object[]])]
 [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/New-Password.md#new-password',
  SupportsShouldProcess,
  ConfirmImpact = 'Low')]
 Param
 (
  [int]$Length = 32,
  [int]$Count = 10,
  [switch]$Strong,
  [switch]$asSecureString
 )
 Begin {
  switch ($Strong) {
   $true {
    [string]$Characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 !@#$%^&*()_+{}|[]\:;'<>?,./`~"
   }
   $false {
    [string]$Characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
   }
  }
  $Passwords = @()
 }
 Process {
  if ($PSCmdlet.ShouldProcess("New", "New Password")) {
   for ($Counter = 1; $Counter -le $Count; $Counter++) {
    $bytes = new-object "System.Byte[]" $Length
    $rnd = new-object System.Security.Cryptography.RNGCryptoServiceProvider
    $rnd.GetBytes($bytes)
    $result = ""
    for ( $i = 0; $i -lt $Length; $i++ ) {
     $result += $Characters[ $bytes[$i] % $Characters.Length ]
    }
    if ($asSecureString) {
     $SecurePassword = New-Object securestring;
     foreach ($Char in $result.ToCharArray()) {
      $SecurePassword.AppendChar($Char);
     }
     $Passwords += $SecurePassword;
    }
    else {
     $Password = New-Object -TypeName PSobject -Property @{
      Password = $result
     }
     $Passwords += $Password
    }
   }
  }
 }
 End {
  Return $Passwords
 }
}