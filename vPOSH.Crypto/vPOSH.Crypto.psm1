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
        [Parameter(Mandatory = $true)]
        [string]$KeyFile,
        [Parameter(Mandatory = $false)]
        [ValidateSet(128, 192, 256)]
        [int]$KeyStrength = 256
    )

    [byte[]]$Key

    switch ($KeyStrength)
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

    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($Key)
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
        [Parameter(Mandatory = $true)]
        [securestring]$Password,
        [Parameter(Mandatory = $true)]
        [string]$KeyFile,
        [Parameter(Mandatory = $true)]
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
        [Parameter(Mandatory = $true)]
        [string]$KeyFile,
        [Parameter(Mandatory = $true)]
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
        [Parameter(Mandatory = $true)]
        [string]$UserName,
        [Parameter(Mandatory = $true)]
        [string]$KeyFile,
        [Parameter(Mandatory = $true)]
        [string]$PasswordFile
    )

    [Byte[]]$SecureKey = [System.Convert]::FromBase64String($(Get-Content -Path $KeyFile))
    return New-Object PSCredential($UserName, (Get-Content -Path $PasswordFile | ConvertTo-SecureString -Key $SecureKey))
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
    <#
    .SYNOPSIS
        Create a random password
    .DESCRIPTION
        Create a random password with some advanced functionality
    .EXAMPLE
        New-RandomPassword.ps1 -ExcludedCharacters '@','I','l','!' -MinimumLength 10 -MaximumLength 42

        Exclude the characters @,I,l, and ! from the generated password and set the minimum
        length to 10 characters and maximum length to 42 characters long.
    .EXAMPLE
        New-RandomPassword.ps1 -ExcludedCharacters '@','I','l','!','_','`' -NonDuplicating

        Exclude the characters @,I,l, and ! from the generated password and do not reuse any characters in
        the generated password
    #>

    [CmdletBinding()]
    param
    (
        # Minimum length of generated password, 15 by default
        [Parameter(Mandatory = $False)]
        [int]$MinimumLength = 15,

        # Maximum length of the generated password, 25 by default
        [Parameter(Mandatory = $False)]
        [int]$MaximumLength = 25,

        # Array list of characters to exclude from the password
        [Parameter(Mandatory = $False)]
        [string[]]$ExcludedCharacters,

        # Do not allow for duplicated characters
        [Parameter(Mandatory = $False)]
        [switch]$NonDuplicating
    )

    $LC_Letters = [int][char]'a'..[int][char]'z' |
    ForEach-Object { [char]$_ }
    $UC_Letters = [int][char]'A'..[int][char]'Z' |
    ForEach-Object { [char]$_ }

    [System.Collections.ArrayList]$Digits = 0..9
    [System.Collections.ArrayList]$SpecialChars = @(
        '~', '`', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')'
        '_', '-', '+', '=', '{', '}', '[', ']', '\', '|', ':', ';'
        '<', '>', ',', '.', '?', '/'
    )

    # Gather them all together into a new ArrayList
    [System.Collections.ArrayList]$FullCharSet = { $LC_Letters + $UC_Letters + $Digits + $SpecialChars }.Invoke()

    # If there's any Excluded Characters, remove them from the FullCharSet now
    if ($ExcludedCharacters.Length -gt 0)
    {
        foreach ($exChar in $ExcludedCharacters)
        {
            $FullCharSet.Remove($exChar)
        }
    }

    $PwdLength = (Get-Random -Minimum $MinimumLength -Maximum $MaximumLength)

    # Check to make sure if we are in NonDuplicating mode we have enough Characters in the FullCharSet
    if ($NonDuplicating)
    {
        if ($PwdLength -gt $FullCharSet.Count)
        {
            Write-Error "Your chosen password is longer than the available character set and you've specified NonDuplicating mode"
            exit 99
        }
    }

    $Password = ''

    foreach ($Item in 1..$PwdLength)
    {
        $IsDupe = $True
        while ($IsDupe)
        {
            $NewChar = Get-Random -InputObject $FullCharSet -Count 1

            # If we are in NonDuplicating mode, then remove the charactor from the FullCharSet
            if ($NonDuplicating)
            {
                $FullCharSet.Remove($NewChar)
            }

            if (($Password.Length -eq 0) -or
                # test for 2-in-a-row
                (($Password.Length -eq 1) -and ($Password -cne $NewChar)) -or
                # test for 3-in-a-row
                (($Password.Length -gt 1) -and ($Password[-1] -cne $NewChar) -and ($Password[-2] -cne $Password[-1]))
            )
            {
                $Password += $NewChar
                $IsDupe = $False
            }
            # else
            # {
            #     $Password
            #     $NewChar
            # }
        }
    }

    return $Password
}
