<#
.SYNOPSIS 
Convert a certificate in PFX format to extract its public key .crt and its private key .key without password in PEM format

.DESCRIPTION
Convert a certificate in PFX format to extract its public key .crt and its private key .key without password in PEM format

.PARAMETER inputPFX
Path to the input .pfx file

.PARAMETER opensslpath
Path to directory where OpenSSL binaries are located and openssl.exe can be found

.PARAMETER password
Import password of the given PFX file mandatory for the convertion.

.EXAMPLE
C:\PS> .\Get-PemFromPFX.ps1


.EXAMPLE
C:\PS> .\Get-PemFromPFX.ps1 -inputPFX C:\PSGallery\resalao.macario.local.pfx -password "MyP@assw0rd"

#>

function Get-PemFromPFX {
[CmdletBinding()]
    param(
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
        [string]$inputPFX,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
        [string]$opensslpath="C:\OpenSSL-Win64\bin\",
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
        [string]$password=""        
        )
    
    #Check OpenSSL path
    if(test-path "$opensslpath\openssl.exe"){
            #Check Input PFX file
            if(test-path "$inputPFX"){
                $PFXdir=Get-ChildItem -Path $inputPFX
                $dirname=$PFXdir.Directory
                $filename=$PFXdir.Basename
                $PEMcrt="$dirname\$filename.crt"
                $PEMkey="$dirname\$filename.key"

                #OpenSSL convert commands
                & "$opensslpath\openssl.exe" pkcs12 -in $inputPFX -nocerts -out $PEMkey -passin pass:$password -passout pass:t0r_m1asXxeq2=022YQ 2> $null
                & "$opensslpath\openssl.exe" pkcs12 -in $inputPFX -clcerts -nokeys -out $PEMcrt -passin pass:$password 2> $null
                & "$opensslpath\openssl.exe" rsa -in $PEMkey -out $PEMkey -passin pass:t0r_m1asXxeq2=022YQ 2> $null

                if ((get-item $PEMkey).Length -gt 0kb){
                    Write-Host "Convert of $inputPFX completed. Output $PEMcrt and $PEMkey " -ForegroundColor Green
                } else {
                    Write-Host "Convert of $inputPFX failed. Probably provided input password was not correct " -ForegroundColor Red
                }

                
        } else {
                Write-Host "Input PFX file cannot be found at $inputPFX" -ForegroundColor Red
        }
    } else {
            Write-Host "OpenSSL cannot be found at $opensslpath. You can download from https://slproweb.com/download/Win64OpenSSL_Light-1_1_0c.exe and install it with default values" -ForegroundColor Red
    }
}
