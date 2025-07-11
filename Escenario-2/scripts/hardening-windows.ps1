# Hardening básico de Windows Server según CIS
Set-ExecutionPolicy Bypass -Scope Process -Force

# Deshabilitar servicios innecesarios
Stop-Service -Name 'Spooler'
Set-Service -Name 'Spooler' -StartupType Disabled

# Políticas de contraseña
net accounts /minpwlen:14 /maxpwage:30 /lockoutthreshold:5

# Habilitar BitLocker
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly

# Habilitar auditoría avanzada
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable