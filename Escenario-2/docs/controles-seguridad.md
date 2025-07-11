# Controles de Seguridad Implementados

## 1. Hardening conforme a CIS/NIST

### Windows Server
- Aplicar **CIS Benchmarks** (automatizable vía Ansible, PowerShell o AWS Systems Manager).
- Deshabilitar servicios innecesarios, reforzar políticas de contraseñas y bloqueo.
- Configurar auditing avanzado y BitLocker para cifrado de disco.
- Uso de **AWS Systems Manager State Manager** para mantener configuración.

### Amazon Linux
- CIS Benchmark (nivel 1) aplicado con scripts Bash y AWS SSM Documents.
- Deshabilitar root login por SSH, forzar autenticación por clave y MFA.
- Instalación de agentes de seguridad (AWS Inspector, CloudWatch, GuardDuty).
- Parches automáticos críticos vía SSM Patch Manager.

### IAM y Security Groups
- Principio de **menor privilegio** en IAM (roles, políticas personalizadas).
- MFA obligatorio para administradores.
- Security Groups restrictivos: solo tráfico necesario (puertos mínimos abiertos), subredes privadas para sistemas críticos.
- Uso de **AWS Network Firewall** para segmentación adicional.

## 2. Compliance por tipo de instancia

| Tipo de Instancia | Framework | Controles Aplicados |
|-------------------|-----------|--------------------|
| Windows Server    | CIS, NIST | Hardening, BitLocker, SSM, CloudWatch, Inspector, IAM, Security Groups |
| Amazon Linux      | CIS, NIST | Hardening, SSM, Inspector, IAM, Security Groups |
| Controladores Biométricos | NIST, GDPR | Cifrado, IAM restringido, registros de acceso, monitoreo continuo |

---