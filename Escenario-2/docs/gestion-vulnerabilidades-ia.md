# Gestión de Vulnerabilidades usando IA

## Esquema Propuesto

1. **Identificación:**
   - Uso de AWS Inspector para escaneo automático.
   - Integración de findings a motor IA (SageMaker) que prioriza según contexto (exposición, criticidad de activos, patrones históricos).

2. **Clasificación:**
   - IA etiqueta findings según criticidad (CVSS, exposición real, impacto en operaciones).

3. **Remediación:**
   - Parches críticos automatizados vía SSM Patch Manager.
   - Notificación a equipo vía SNS/Slack para intervención manual si es necesario.

## SLA de Remediación

| Severidad | Tiempo Máximo de Remediación |
|-----------|-----------------------------|
| Crítico   | 24 horas                    |
| Alto      | 72 horas                    |
| Medio     | 7 días                      |
| Bajo      | 30 días                     |

## Flujo Automatizado

1. Escaneo diario.
2. Priorización automática.
3. Remediación automática/manual.
4. Reporte de cierre.

---