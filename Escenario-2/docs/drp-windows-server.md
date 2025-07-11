# DRP - Plan de Recuperación ante Desastres (Windows Server)

## Objetivo
Garantizar recuperación total de sistemas críticos Windows Server en menos de 1 hora (RTO <1h, RPO <1h).

## Procedimiento

1. **Backups automáticos** diarios (AWS Backup, snapshots EBS).
2. Replicación de backups en región secundaria.
3. Scripts de restauración documentados y probados cada 6 meses.
4. Prueba de DRP semestral (simulación de desastre).
5. Documentación y checklist de pasos para restauración.

## Ejemplo de Ejercicio DRP

- Simulación de pérdida total de instancia.
- Restaurar desde snapshot más reciente en nueva AZ.
- Verificación de integridad y continuidad de servicios.
- Documentación de tiempos y lecciones aprendidas.

---