# Laboratorio SOC con Microsoft Sentinel

## Descripción

Laboratorio práctico de ciberseguridad orientado a simular actividades realizadas por un analista SOC utilizando Microsoft Sentinel.

El proyecto implementa un flujo completo de monitoreo de seguridad desde un endpoint Windows hacia Microsoft Sentinel, incluyendo recopilación de eventos, análisis mediante KQL, investigación de actividad, desarrollo de detecciones, generación de alertas y análisis de incidentes.

El laboratorio se desarrolla progresivamente, incorporando nuevas fuentes de telemetría, investigaciones y detecciones.

---

## Tecnologías utilizadas

- Microsoft Sentinel
- Microsoft Azure
- Azure Arc
- Azure Monitor Agent (AMA)
- Log Analytics Workspace
- Windows Security Events
- KQL (Kusto Query Language)
- Windows 10
- GitHub

---

## Objetivos del laboratorio

- Centralizar eventos de seguridad de Windows en Microsoft Sentinel.
- Analizar telemetría mediante consultas KQL.
- Investigar eventos de autenticación y creación de procesos.
- Correlacionar diferentes eventos de seguridad.
- Analizar relaciones entre procesos padre e hijo.
- Crear reglas de detección mediante Analytics Rules.
- Generar y analizar alertas e incidentes.
- Aplicar procesos de triage y clasificación.
- Documentar investigaciones siguiendo un flujo de trabajo SOC.
- Incorporar MITRE ATT&CK cuando la evidencia permita asociar técnicas.
- Utilizar Python posteriormente para apoyar tareas de análisis y automatización.

---

## Arquitectura

```text
Windows Endpoint
      │
      ▼
Azure Arc
      │
      ▼
Azure Monitor Agent (AMA)
      │
      ▼
Data Collection Rule (DCR)
      │
      ▼
Log Analytics Workspace
      │
      ▼
Microsoft Sentinel
      │
      ├── KQL
      ├── Investigaciones
      ├── Analytics Rules
      ├── Alertas
      └── Incidentes
```

---

# Investigaciones

## INC-001 — Análisis de múltiples intentos fallidos de autenticación

Investigación de eventos de autenticación de Windows utilizando Event ID 4625 y Event ID 4624.

Se identificaron múltiples intentos fallidos de inicio de sesión para una misma cuenta dentro de un período corto y posteriormente se correlacionaron con una autenticación exitosa.

Durante el análisis se utilizaron campos como:

- Account
- Computer
- IpAddress
- LogonType
- TimeGenerated

La correlación permitió determinar que la actividad correspondía a una prueba controlada dentro del laboratorio y no existían indicadores suficientes para considerarla actividad maliciosa.

**Habilidades aplicadas:** análisis de autenticación, KQL, correlación temporal, Event ID 4625/4624 y triage SOC.

[Ver investigación completa](Investigaciones/INC-001-analisis-autenticacion/investigacion.md)

---

## INC-002 — Análisis de creación y relación de procesos

Investigación de eventos de creación de procesos de Windows mediante Event ID 4688.

Se analizaron ejecuciones de PowerShell y Notepad para estudiar relaciones entre procesos padre e hijo.

Durante la investigación se habilitó y analizó información de línea de comandos y se utilizaron identificadores de proceso para reconstruir relaciones de ejecución.

Se consiguió correlacionar:

```text
explorer.exe
     │
     ▼
powershell.exe
     │
     ▼
powershell.exe
     │
     └── CommandLine
```

La relación padre-hijo fue validada mediante la correlación entre `NewProcessId` y `ProcessId` y posteriormente automatizada mediante una consulta KQL.

**Habilidades aplicadas:** Event ID 4688, análisis de procesos, PID correlation, CommandLine, process tree, KQL y endpoint investigation.

[Ver investigación completa](Investigaciones/INC-002-analisis-creacion-procesos/investigacion.md)

---

# Detecciones

## DET-001 — Múltiples intentos fallidos de inicio de sesión

Regla de detección desarrollada en Microsoft Sentinel para identificar cuentas con 3 o más intentos fallidos de autenticación dentro de una ventana de 5 minutos.

La detección utiliza eventos Event ID 4625 y fue implementada como una Scheduled Analytics Rule.

La regla incluye:

- Consulta KQL.
- Umbral de detección.
- Entity Mapping.
- Custom Details.
- Generación automática de alertas.
- Creación de incidentes.
- Proceso de triage y clasificación.

Durante la validación controlada se generaron seis intentos fallidos, provocando correctamente una alerta y un incidente en Microsoft Sentinel.

La investigación posterior determinó que correspondía a una prueba de seguridad controlada.

**Habilidades aplicadas:** Detection Engineering, Analytics Rules, KQL, Entity Mapping, alert triage e incident investigation.

[Ver detección completa](detecciones/DET-001-multiples-intentos-fallidos/README.md)

---

# Flujo de trabajo SOC

El laboratorio busca reproducir progresivamente un flujo de trabajo similar al utilizado en operaciones de seguridad:

```text
Telemetría
    ↓
Microsoft Sentinel
    ↓
Consulta KQL
    ↓
Detección
    ↓
Alerta
    ↓
Incidente
    ↓
Triage
    ↓
Recolección de evidencia
    ↓
Correlación
    ↓
Clasificación
    ↓
Cierre / Escalamiento
```

---

# Estado del laboratorio

| Componente | Estado |
|---|---|
| Integración Windows → Sentinel | Completado |
| Windows Security Events | Completado |
| Investigación de autenticación | Completado |
| Detección de múltiples intentos fallidos | Completado |
| Generación de alertas e incidentes | Completado |
| Investigación de creación de procesos | Completado |
| Correlación padre-hijo mediante PID | Completado |
| Análisis avanzado de PowerShell | En desarrollo |
| Sysmon | Pendiente |
| MITRE ATT&CK | Pendiente |
| Herramientas Python | Pendiente |

---

# Estructura del proyecto

```text
SOC-Sentinel-Lab/
│
├── README.md
│
├── configuracion/
│   └── Configuración del entorno Microsoft Sentinel
│
├── Investigaciones/
│   ├── INC-001-analisis-autenticacion/
│   └── INC-002-analisis-creacion-procesos/
│
├── detecciones/
│   └── DET-001-multiples-intentos-fallidos/
│
└── herramientas-python/
    └── Próximamente
```

---

## Próximas etapas

El laboratorio continuará incorporando nuevas capacidades de análisis y detección, incluyendo:

- Análisis avanzado de ejecuciones de PowerShell.
- Telemetría de Sysmon.
- Reconstrucción de process trees más complejos.
- Nuevas reglas de detección en Microsoft Sentinel.
- Mapeo de actividad a MITRE ATT&CK cuando exista evidencia suficiente.
- Desarrollo de herramientas Python para apoyar investigaciones SOC.

