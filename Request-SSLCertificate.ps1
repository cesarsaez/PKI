<#

.SYNOPSIS 
Requests a certificate from a Windows Enterprise CA and gets its certificate with private key as .pfx and convert it to PEM format obtaining the public key .crt and the privite key .key

.DESCRIPTION
Requests a certificate from a Windows Enterprise CA and gets its certificate with private key as .pfx and convert it to PEM format obtaining the public key .crt and the privite key .key

You must specify at least the Subject for the subject name.
    
.PARAMETER subject
Specifies the common name for the subject of the certificate(s).Use the FQDN format, e.g my.website.tld

.PARAMETER SANs
Specifies the Subject Alternative Name for the certifiacate. Use the FQDN formant and comma separate valies, e.g sub.my.domain.tld,alt-my.domain.tld

.PARAMETER OnlineCA
Specifies the name of the ADCS Enterprise CA to sumbit the request. Use format CAserver01.Company.local\MyCompamy-CA. You can use "certutil -dump" to list available CA, but note that not all certificate templates could be available at all listed CAs.

.PARAMETER CATemplate
Specifies the name of the certificate tempalte to use for the certificate signature.Use "certutil -ADTemplate" to list templates names and allowed ones. Use shortname.

.EXAMPLE
C:\PS> .\Request-SSLCertificate.ps1 -subject my.website.tld

.EXAMPLE
C:\PS> .\Request-SSLCertificate.ps1 -subject my.website.tld -SANs sub.my.domain.tld,alt-my.domain.tld -OnlineCA CAserver01.Company.local\MyCompamy-CA

.NOTES
Version    : 1.0 Based on the original script from https://blog.kloud.com.au/2013/07/30/ssl-san-certificate-request-and-import-from-powershell/
File Name  : Request-SSLCertificate.ps1
Requires   : PowerShell V3
Author:    : Cesar SAEZ


#>
function Request-SSLCertificate {
    param (
        [Parameter(Mandatory=$true, HelpMessage = "Please enter the subject in FQDN format: e.g. my.website.tld")]
        [ValidateScript({If ($_ -match "^(\*\.)?([a-z\d][a-z\d-]*[a-z\d]\.)+[a-z]+$") {
                         $True
                 } Else {
                         Throw "$_ is not valid CN use a FQDN format my.website.tld"
                 }})]
        [string]$subject,
        [Parameter(Mandatory=$false, HelpMessage = "Please enter the SAN domains as a comma separated list")]
        [array]$SANs,
        #[ValidateSet('SUBCA02.gaseosa.local\MACLAB-SUBCA02','rootca01.macario.local\Gaseosa-CA')]
        [Parameter(Mandatory=$false, HelpMessage = "Please enter the Online Certificate Authority")]
        [string]$OnlineCA,
        [Parameter(Mandatory=$false, HelpMessage = "Please enter the Online Certificate Authority")]
        [string]$CATemplate = "CSRWebServer"
    )
 
    ### Preparation
    $subjectDomain = $subject.split(',')[0].split('=')[0]
    if ($subjectDomain -match "\*.") {
        $subjectDomain = $subjectDomain -replace "\*", "star"
    }
   #$subjectDomain = $subject
    $CertificateINI = "$subjectDomain.ini"
    $CertificateREQ = "$subjectDomain.req"
    $CertificateRSP = "$subjectDomain.rsp"
    $CertificateCER = "$subjectDomain.cer"
    $CertificatePFX = "$subjectDomain.pfx"
    $CertificatePasswd = "$subjectDomain.txt"
    $CertificateZIP = "$subjectDomain.zip"
 
    ### INI file generation
    new-item -type file $CertificateINI -force
    add-content $CertificateINI '[Version]'
    add-content $CertificateINI 'Signature="$Windows NT$"'
    add-content $CertificateINI ''
    add-content $CertificateINI '[NewRequest]'
    $temp = 'Subject="cn=' + $subject + '"'
    add-content $CertificateINI $temp
    add-content $CertificateINI 'Exportable=TRUE'
    add-content $CertificateINI 'KeyLength=2048'
    add-content $CertificateINI 'KeySpec=1'
    add-content $CertificateINI 'KeyUsage=0xA0'
    add-content $CertificateINI 'MachineKeySet=True'
    add-content $CertificateINI 'ProviderName="Microsoft RSA SChannel Cryptographic Provider"'
    add-content $CertificateINI 'ProviderType=12'
    add-content $CertificateINI 'SMIME=FALSE'
    add-content $CertificateINI 'RequestType=PKCS10'
    add-content $CertificateINI '[Strings]'
    add-content $CertificateINI 'szOID_ENHANCED_KEY_USAGE = "2.5.29.37"'
    add-content $CertificateINI 'szOID_PKIX_KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"'
    add-content $CertificateINI 'szOID_PKIX_KP_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"'
    if ($SANs) {
        add-content $CertificateINI 'szOID_SUBJECT_ALT_NAME2 = "2.5.29.17"'
        add-content $CertificateINI '[Extensions]'
        add-content $CertificateINI '2.5.29.17 = "{text}"'
        #Retro compatibility some apps, SAN must contain CN at SAN
        $tmpSAN='_continue_ = "dns=' + $subject + '&"'
        add-content $CertificateINI $tmpSAN
        foreach ($SAN in $SANs) {
            $temp = '_continue_ = "dns=' + $SAN + '&"'
            add-content $CertificateINI $temp
        }
    }
 
    ### Certificate request generation
    if (test-path .\$CertificateREQ) {remove-item .\$CertificateREQ -force}
    certreq -new $CertificateINI $CertificateREQ
 
    ### Online certificate request and import
    if ($OnlineCA) {
        
        if (test-path .\$CertificateRSP) {remove-item .\$CertificateRSP -force}
        certreq -submit -attrib "CertificateTemplate:$CATemplate" -config $OnlineCA $CertificateREQ $CertificateCER
 
        certreq -accept $CertificateCER
    }
    ### Export as PFX
    #Import issued .cer into CurrentUser cert store to select its Thumbprint
    $latestCurrUsercert=Import-Certificate -FilePath .\$CertificateCER -CertStoreLocation Cert:\CurrentUser\My 
    $CurrUserthumb=$latestCurrUsercert.thumbprint
    
    #Generate random password
    $randomstr=([char[]]([char]'a'..[char]'z') + 0..9 + [char[]]([char]'A'..[char]'Z') + [Char[]]'!#$%&*+-.:=@_'| sort {get-random})[0..12] -join ''
    $mypwd = ConvertTo-SecureString -String "$randomstr" -Force �AsPlainText
    #Export PFX
    Get-ChildItem -Path cert:\localMachine\my\$CurrUserthumb | Export-PfxCertificate -FilePath .\$CertificatePFX -Password $mypwd -Force
    #
    set-content .\$CertificatePasswd $randomstr
    
    #Convert PFX to PEM
    if(test-path "$opensslpath\openssl.exe"){
            #Check Input PFX file
            if(test-path "$CertificatePFX"){
                $PFXdir=Get-ChildItem -Path $CertificatePFX
                $dirname=$PFXdir.Directory
                $filename=$PFXdir.Basename
                $PEMcrt="$dirname\$filename.crt"
                $PEMkey="$dirname\$filename.key"

                #OpenSSL convert commands
                & "$opensslpath\openssl.exe" pkcs12 -in $CertificatePFX -nocerts -out $PEMkey -passin pass:$randomstr -passout pass:$randomstr 2> $null
                & "$opensslpath\openssl.exe" pkcs12 -in $CertificatePFX -clcerts -nokeys -out $PEMcrt -passin pass:$randomstr 2> $null
                & "$opensslpath\openssl.exe" rsa -in $PEMkey -out $PEMkey -passin pass:$randomstr 2> $null

                if ((get-item $PEMkey).Length -gt 0kb){
                    Write-Host "Convert of $CertificatePFX completed. Output $PEMcrt and $PEMkey " -ForegroundColor Green
                } else {
                    Write-Host "Convert of $CertificatePFX failed. Probably provided input password was not correct " -ForegroundColor Red
                }

                
        } else {
                Write-Host "Input PFX file cannot be found at $CertificatePFX" -ForegroundColor Red
        }
    } else {
            Write-Host "OpenSSL cannot be found at $opensslpath. You can download from https://slproweb.com/download/Win64OpenSSL_Light-1_1_0c.exe and install it with default values" -ForegroundColor Red
    }

    #Cleanup of tmp files
    Remove-Item .\$CertificateCER -Force -ea SilentlyContinue
    Remove-Item .\$CertificateINI -Force -ea SilentlyContinue
    Remove-Item .\$CertificateREQ -Force -ea SilentlyContinue
    Remove-Item .\$CertificateRSP -Force -ea SilentlyContinue
    Remove-Item .\$CertificateCER -Force -ea SilentlyContinue

    #Compress required files and password protect them using 7zip
    $randomstrZIP=([char[]]([char]'a'..[char]'z') + 0..9 + [char[]]([char]'A'..[char]'Z') + [Char[]]'!#$%&*+-.:=@_'| sort {get-random})[0..12] -join ''
    $7zip = "C:\Program Files\7-Zip\7z.exe"
    $destZip = $CertificateZIP
    $sourceFiles = "$subjectDomain.*"
    $zipPassFile= "$subjectDomain-zip.txt"
    
    if(test-path "$7zip"){
        Start-Process $7zip -ArgumentList "a $destZip $sourceFiles -p$randomstrZIP"
        set-content $zipPassFile $randomstrZIP
        
       

        Write-Host "Certificate file $CertificatePFX, $PEMcrt, $PEMkey and $CertificatePasswd with import password for the .pfx commpresed at $destZip, password for zip file $zipPassFile " -ForegroundColor Green

    } else {
        Write-host "Missing 7-zip executable required to zip with password, installing..." -BackgroundColor Red
        $url = "http://www.7-zip.org/a/7z1604-x64.msi"
        $output = ".\7z1604-x64.msi"
        Invoke-WebRequest -Uri $url -OutFile $output
        MSIEXEC /i $output  /quiet /norestart
        remove-item $output

    }

    
    #Cleanup of cert stores
    $cert = Get-Childitem "cert:\CurrentUser\My" | where-object {$_.Thumbprint -eq $CurrUserthumb}
    $certstoreCurrentUser = new-object system.security.cryptography.x509certificates.x509Store('My', 'CurrentUser')
	$certstoreCurrentUser.Open('ReadWrite')
	$certstoreCurrentUser.Remove($cert)
    $certstoreCurrentUser.close() 

    $certstoreLocalMachine = new-object system.security.cryptography.x509certificates.x509Store('My', 'LocalMachine')
	$certstoreLocalMachine.Open('ReadWrite')
	$certstoreLocalMachine.Remove($cert)
    $certstoreLocalMachine.close()

    #Cleanup of tmp2 files
    Remove-Item $CertificatePFX -force -ea SilentlyContinue
    Remove-Item $CertificatePasswd -force -ea SilentlyContinue
    Remove-Item $PEMcrt -force -ea SilentlyContinue
    Remove-Item $PEMkey -force -ea SilentlyContinue

}
