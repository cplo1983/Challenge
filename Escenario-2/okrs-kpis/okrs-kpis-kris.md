# OKRs, KPIs y KRIs del Proyecto de Seguridad en AWS

## OKRs (Objectives & Key Results)

**OKR 1:** Alinear el 100% de la infraestructura AWS a controles CIS/NIST.
- KR1: 100% de instancias auditadas y alineadas a CIS/NIST.
- KR2: 0 findings críticos de cumplimiento en auditorías mensuales.

**OKR 2:** Reducir el tiempo de remediación de vulnerabilidades críticas por debajo de 24 horas.
- KR1: SLA de remediación de vulnerabilidades críticas cumplido 98% del tiempo.
- KR2: Automatización de procesos de remediación en al menos el 90% de los casos.

**OKR 3:** Garantizar un uptime mensual superior al 99.999% para servicios críticos.
- KR1: No más de 5 minutos de inactividad mensual en aplicaciones clave.
- KR2: Ejercicios DRP exitosos al menos dos veces al año.

## KPIs (Key Performance Indicators)

- % de cumplimiento CIS/NIST por tipo de instancia.
- Tiempo promedio de remediación de vulnerabilidades (por severidad).
- Uptime mensual de sistemas críticos.

## KRIs (Key Risk Indicators)

- Número de accesos no autorizados detectados por IAM/CloudTrail.
- Número de vulnerabilidades críticas abiertas >24h.
- Número de fallos de backup/restauración en pruebas DRP.

## Ejemplo de métricas y herramientas de medición

- **AWS Config** para compliance.
- **Security Hub** para findings y SLA.
- **CloudWatch** para uptime y alertas.
- **SNS/Email** para notificación de riesgos.

---

## Principales riesgos mitigados

1. **Acceso no autorizado a sistemas críticos**
   - KRI: Accesos fallidos/no autorizados por IAM.
2. **Vulnerabilidades sin remediar**
   - KRI: Vulnerabilidades críticas sin cerrar en 24h.
3. **Fallo en recuperación ante desastres**
   - KRI: Fallos en pruebas de restauración y DRP.

---