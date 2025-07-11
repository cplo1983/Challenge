#!/bin/bash
# Hardening básico Amazon Linux según CIS
set -e

# Deshabilitar root login por SSH
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl reload sshd

# Forzar autenticación por clave y MFA
yum install -y google-authenticator
echo "auth required pam_google_authenticator.so" >> /etc/pam.d/sshd

# Actualizar y aplicar parches críticos
yum update -y

# Instalar y habilitar auditd
yum install -y audit
systemctl enable --now auditd