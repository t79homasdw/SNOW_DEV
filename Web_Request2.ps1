param(
    [string]$sub,
    [string]$fn,
    [string]$sans_input,
    [string]$email,
    [string]$ritm
    )

Remove-Item -Path "C:\Certreq\*" -Recurse -Force -ErrorAction SilentlyContinue
copy-item -path "C:\Cert_Config\root.crt" -Destination C:\Certreq -Force
$path = "C:\Certreq\requestconfig.inf"

<#
$sub = "www.archgroup.com"
$fn = "Wildfire"
$sans_input = "www.arch.com,www.buttler.com,www.fieldtype.com,www.beanbag.com"
$email_chain = "amis-domainhybridteam_corp@archgroup.com,dthomas@archgroup.com"
#>

$subject = $sub -replace(' ')
$fname = $fn -replace(' ')
$sans1 = $sans_input -replace(' ')
$sans = $sans1.Split(",")

$f_name2 = $sub.replace('.','_')
$res = $f_name2 + ".crt"
$key = $f_name2 + ".key"
$r_path = "C:\CertReq\" + $res
$k_path = "C:\CertReq\" + $key
$rsp = "C:\CertReq\" + $f_name2 + ".rsp"

$f_subject = 'Subject = "CN=' + $subject + '"'
$f_name = 'FriendlyName = "' + $fname + '"'

#Build out requestconfig.inf
Remove-Item -Path $path -Force -ErrorAction SilentlyContinue

echo '[Version]' | out-file -FilePath $path -Append
echo 'Signature="$Windows NT$"' | out-file -FilePath $path -Append
echo '[NewRequest]' | out-file -FilePath $path -Append
echo $f_subject | out-file -FilePath $path -Append
echo 'Exportable = TRUE' | out-file -FilePath $path -Append
echo 'KeyLength = 2048' | out-file -FilePath $path -Append
echo 'KeySpec = 1' | out-file -FilePath $path -Append
echo 'KeyUsage = 0xa0' | out-file -FilePath $path -Append
echo 'MachineKeySet = TRUE' | out-file -FilePath $path -Append
echo 'ProviderName = "Microsoft RSA SChannel Cryptographic Provider"' | out-file -FilePath $path -Append
echo 'RequestType = PKCS10' | out-file -FilePath $path -Append
echo $f_name  | out-file -FilePath $path -Append
echo 'MachineKeySet = True' | out-file -FilePath $path -Append
echo '[RequestAttributes]' | out-file -FilePath $path -Append
echo 'CertificateTemplate = "1.3.6.1.4.1.311.21.8.5754529.15516722.14634894.4584216.14836698.222.16490604.2262254"' | out-file -FilePath $path -Append
echo '[EnhancedKeyUsageExtension]' | out-file -FilePath $path -Append
echo 'OID=1.3.6.1.5.5.7.3.1 ; Server Authentication' | out-file -FilePath $path -Append
echo '[Extensions]' | out-file -FilePath $path -Append
echo '2.5.29.17 = "{text}"' | out-file -FilePath $path -Append

foreach ($s in $sans){
$output = '_continue_ = "dns=' + $s + '&"'
Write-Host $output
echo $output | out-file -FilePath $path -Append
}


cd \
cd Certreq

certreq -new -q -config "AMIS-DWCDC001.archgrouptest.io\archgrouptest-AMIS-DWCDC001-CA" C:\Certreq\requestconfig.inf C:\Certreq\certreq.req
certreq -submit -config "AMIS-DWCDC001.archgrouptest.io\archgrouptest-AMIS-DWCDC001-CA" certreq.req $r_path $k_path
$cert = Import-Certificate -FilePath $r_path -CertStoreLocation Cert:\LocalMachine\My
$CertFile = "C:\Cert_Config\Cert_Passwd.txt"

$cert_content = (Get-Content $CertFile)
$mypwd = ConvertTo-SecureString $cert_content
$thumb = $cert.Thumbprint

$p_cert = "Cert:\LocalMachine\My\" + $thumb
$p_file = "C:\Certreq\" + $f_name2 + ".pfx"
$params1 = $null

$params1 = @{
    Cert = $p_cert
    FilePath = $p_file
    ChainOption = 'BuildChain'
    NoProperties = $false
    Password = $mypwd
    Force = $true
}

Export-PfxCertificate @params1
$cert | remove-item
$response = "C:\Certreq\" + $f_name2 + ".rsp"

Remove-Item -Path "C:\Certreq\requestconfig.inf" -force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Certreq\certreq.req" -force -ErrorAction SilentlyContinue
Remove-Item -Path $response -force -ErrorAction SilentlyContinue

mkdir "c:\Certreq\$ritm"
$7zipPath = "$env:ProgramFiles\7-Zip\7z.exe"
Set-Alias Start-SevenZip $7zipPath
$Source = "c:\Certreq\*.*"
$Target = "C:\Cert_Out\" + $ritm + "\" + $f_name2 + ".zip"
Start-SevenZip a -mx=9 $Target $Source

Remove-Item -Path "C:\Certreq\*" -Recurse -Force -ErrorAction SilentlyContinue

cd C:\Cert_Config

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$User = "MS_u2a49d@trial-z3m5jgrwnmoldpyo.mlsender.net"
$File = "C:\Cert_Config\Email_Passwd.txt"
$email_pass = Get-Content $File
$pass = $email_pass | ConvertTo-SecureString
$cred=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User,$pass


$EmailTo = $email
$EmailFrom = $User
$Subject = $f_subject
$body= "Congratulations Here is the certificate that you requested."
$smtpserver = "smtp.mailersend.net"
$filenameAndPath = $Target
$smtpmessage = New-Object System.Net.Mail.MailMessage($EmailFrom,$EmailTo,$Subject,$body)
$attachment = New-Object System.Net.Mail.Attachment($filenameAndPath)
$SMTPMessage.Attachments.Add($attachment)
$SMTPClient = New-Object Net.Mail.SmtpClient($SMTPServer, 587)
$SMTPClient.EnableSsl = $true
$SMTPClient.Credentials = New-Object System.Net.NetworkCredential($cred.UserName,$pass);
$SMTPClient.Send($SMTPMessage)

<#
$sendMailMessageSplat = @{
    From = $User
    To = $email
    Subject = $f_subject
    Body = $body
    Credential = $cred
    UseSsl = $true
    Attachments = $Target
    Priority = 'High'
    SmtpServer = 'smtp.mailersend.net'
    Port = 587
}
Send-MailMessage @sendMailMessageSplat
#>
