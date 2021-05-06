<#
    .SYNOPSIS
        Nice module to assist in managing password storage in a file using an assymetrical key
    .DESCRIPTION
        Nice module to assist in managing password storage in a file using an assymetrical key
#>
function New-SecureKey
{
    <#
        .SYNOPSIS
            Creates a key to use for secure password storage
        .DESCRIPTION
            Creates a key to use for secure password storage in a keyfile on the filesystem.
        .PARAMETER KeyFile
            Path to the KeyFile location including the name of the file
        .PARAMETER KeyStrength
            Bitness of the key generated with the options being 128, 192, and 256.  256 is the default
        .EXAMPLE
            New-SecurityKey -KeyFile $env:userprofile\MySecret.txt
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$KeyFile,
        [Parameter(Mandatory=$false)]
        [ValidateSet(128,192,256)]
        [int]$KeyStrength = 256
    )

    [byte[]]$Key

    switch($KeyStrength)
    {
        128
        {
            $key = New-Object byte[] 16
        }
        192
        {
            $key = New-Object byte[] 24
        }
        256
        {
            $key = New-Object byte[] 32
        }
    }

    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
    [System.Convert]::ToBase64String($key) | Set-content -Path $KeyFile
}

function Set-StoredPassword
{
    <#
        .SYNOPSIS
            Using a KeyFile this will encrypt and store a password into a file
        .DESCRIPTION
            Using a KeyFile this will encrypt and store a password into a file
        .PARAMETER Password
            Password to encrypt as a SecureString object
        .PARAMETER KeyFile
            Location of the KeyFile to use for Encryption
        .PARAMETER PasswordFile
            Location to store the encrypted password
        .EXAMPLE
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [securestring]$Password,
        [Parameter(Mandatory=$true)]
        [string]$KeyFile,
        [Parameter(Mandatory=$true)]
        [string]$PasswordFile
    )

    [byte[]]$SecureKey = [System.Convert]::FromBase64String($(Get-Content -Path $KeyFile))
    $Password | ConvertFrom-SecureString -Key $SecureKey | Set-content -Path $PasswordFile
}

function Get-StoredPassword
{
    <#
        .SYNOPSIS
            Using a KeyFile this will decrypt and store a password from a file
        .DESCRIPTION
            Using a KeyFile this will decrypt and store a password from a file
        .PARAMETER KeyFile
            Location of the KeyFile to use for decryption
        .PARAMETER PasswordFile
            Location of the stored the encrypted password
        .EXAMPLE
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$KeyFile,
        [Parameter(Mandatory=$true)]
        [string]$PasswordFile
    )

    [Byte[]]$SecureKey = [System.Convert]::FromBase64String($(Get-Content -Path $KeyFile))
    return [System.Security.SecureString](Get-Content -Path $PasswordFile | ConvertTo-SecureString -Key $SecureKey)
}

function Get-MyCredentials
{
    <#
        .SYNOPSIS
            Creates a Credential Object using the specified key and encrypted Password File.
        .DESCRIPTION
            Creates a Credential Object using the specified key and encrypted Password File.
        .PARAMETER UserName
            String representation of username in the format of domain\username
        .PARAMETER KeyFile
            Location of the KeyFile to use for decryption
        .PARAMETER PasswordFile
            Location of the stored the encrypted password
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$UserName,
        [Parameter(Mandatory=$true)]
        [string]$KeyFile,
        [Parameter(Mandatory=$true)]
        [string]$PasswordFile
    )

    [Byte[]]$SecureKey = [System.Convert]::FromBase64String($(Get-Content -Path $KeyFile))
    return New-Object PSCredential($UserName,(Get-Content -Path $PasswordFile | ConvertTo-SecureString -Key $SecureKey))
}

function Test-FileHash
{
    [cmdletbinding()]
    param
    (
        [string]$HashFile,

        [ValidateSet("SHA256", "SHA384", "SHA512")]
        [string]$HashAlgorithm = "SHA256"
    )

    [int]$FailCount = 0

    $files = Import-Csv -Delimiter " " -Path $HashFile -Header ("FileHash", "FileName")

    foreach ($fileItem in $files)
    {
        $hashObj = Get-FileHash -Path $fileItem.FileName -Algorithm $HashAlgorithm

        Write-Host "$($fileItem.FileName):" -NoNewline

        if ($hashObj.Hash -eq $fileItem.FileHash)
        {
        Write-Host " OK" -ForegroundColor Green
        }
        else
        {
        Write-Host " FAILED" -ForegroundColor Red
        $FailCount ++
        }
    }

    if ($FailCount -gt 0)
    {
        Write-Host "WARNING: 1 computed checksum did NOT match" -ForegroundColor Red
    }
}

function New-RandomPassword
{

}