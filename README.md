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
- Sysmon
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
- Analizar líneas de comandos de PowerShell.
- Mapear detecciones a MITRE ATT&CK.
- Documentar investigaciones siguiendo un flujo de trabajo SOC.
- Utilizar Python posteriormente para apoyar tareas de análisis y automatización.

---

## Arquitectura

```text
Windows Endpoint
      │
      ├── Windows Security Events
      └── Sysmon
              │
              ▼
          Azure Arc
              │
              ▼
     Azure Monitor Agent (AMA)
              │
              ▼
     Data Collection Rules (DCR)
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

# Configuración y fuentes de telemetría

## SYS-001 — Integración de Sysmon con Microsoft Sentinel

Integración de Sysmon como nueva fuente de telemetría del endpoint Windows hacia Microsoft Sentinel.

Se configuró una Data Collection Rule independiente para recopilar eventos del canal:

```text
Microsoft-Windows-Sysmon/Operational
```

Inicialmente se habilitó la recopilación de:

- Event ID 1 — Process Create
- Event ID 3 — Network Connection

Durante la implementación también se diagnosticó un problema de Azure Monitor Agent relacionado con un token expirado que impedía descargar nuevas configuraciones.

Después de reinstalar Azure Monitor Agent se validó correctamente el flujo:

```text
Sysmon
   ↓
Azure Monitor Agent
   ↓
dcr-sysmon-soc-lab
   ↓
Log Analytics Workspace
   ↓
Microsoft Sentinel
```

**Habilidades aplicadas:** Sysmon, Azure Monitor Agent, Data Collection Rules, XPath, Azure Arc, Log Analytics, KQL y troubleshooting de telemetría.

<p align="center">
<a href="configuracion/SYS-001-integracion-sysmon-sentinel/README.md">
<img src="https://img.shields.io/badge/VER_CONFIGURACIÓN_SYS--001-00FF41?style=for-the-badge&logo=microsoftsentinel&logoColor=black&labelColor=000000" />
</a>
</p>

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

<p align="center">
<a href="Investigaciones/INC-001-analisis-autenticacion/Proceso.md">
<img src="https://img.shields.io/badge/VER_INVESTIGACIÓN_INC--001-00FF41?style=for-the-badge&logo=microsoftsentinel&logoColor=black&labelColor=000000" />
</a>
</p>

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

<p align="center">
<a href="Investigaciones/INC-002-analisis-creacion-procesos/investigacion.md">
<img src="https://img.shields.io/badge/VER_INVESTIGACIÓN_INC--002-00FF41?style=for-the-badge&logo=microsoftsentinel&logoColor=black&labelColor=000000" />
</a>
</p>

---

## INC-003 — Investigación de procesos y conexiones de red con Sysmon

Investigación de telemetría Sysmon utilizando Event ID 1 y Event ID 3 para correlacionar la creación de un proceso con una conexión de red realizada por ese mismo proceso.

Durante la prueba controlada se ejecutó PowerShell con:

```text
Test-NetConnection www.microsoft.com -Port 443
```

La investigación permitió relacionar:

```text
Event ID 1 — Process Create
        ↓
ProcessGuid
        ↓
Event ID 3 — Network Connection
```

Se utilizaron campos como:

- ProcessGuid
- ProcessId
- Image
- CommandLine
- Protocol
- DestinationIp
- DestinationPort

Mediante KQL se realizó una correlación utilizando `join` sobre `ProcessGuid`, permitiendo identificar en una sola vista el proceso ejecutado, el comando utilizado y la conexión de red asociada.

La actividad correspondía a una prueba controlada dentro del laboratorio y no se identificó actividad maliciosa.

**Habilidades aplicadas:** Sysmon, Event ID 1, Event ID 3, KQL, `extract()`, `extend`, `join`, ProcessGuid correlation, CommandLine analysis, network analysis y SOC investigation.

<p align="center">
<a href="Investigaciones/INC-003-procesos-conexiones-sysmon/README.md">
<img src="https://img.shields.io/badge/VER_INVESTIGACIÓN_INC--003-00FF41?style=for-the-badge&logo=microsoftsentinel&logoColor=black&labelColor=000000" />
</a>
</p>

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

<p align="center">
<a href="detecciones/DET-001-multiples-intentos-fallidos/README.md">
<img src="https://img.shields.io/badge/VER_Deteccion_DET--001-00FF41?style=for-the-badge&logo=microsoftsentinel&logoColor=black&labelColor=000000" />
</a>
</p>

---

## DET-002 — Ejecución sospechosa de PowerShell

Regla de detección desarrollada en Microsoft Sentinel para identificar ejecuciones de PowerShell que contengan indicadores de línea de comandos que requieran investigación.

La detección utiliza eventos de creación de procesos de Windows mediante **Event ID 4688** y analiza principalmente el campo `CommandLine`.

Entre los indicadores configurados se encuentran:

- `-ExecutionPolicy Bypass`
- `-EncodedCommand`
- `-enc`
- `-WindowStyle Hidden`
- `Invoke-WebRequest`
- `FromBase64String`
- `IEX`

Durante la validación se realizó una ejecución controlada de PowerShell utilizando:

```text
-ExecutionPolicy Bypass
```

La actividad fue detectada correctamente por la regla analítica, generando una alerta y posteriormente un incidente en Microsoft Sentinel.

Durante la investigación se analizaron:

- TimeGenerated
- Account
- Computer
- NewProcessName
- ParentProcessName
- CommandLine

La detección fue asociada con MITRE ATT&CK:

```text
Táctica:
Execution

Técnica:
T1059 — Command and Scripting Interpreter

Subtécnica:
T1059.001 — PowerShell
```

Después del análisis, el incidente fue clasificado como:

```text
Informational, expected activity — Security testing
```

debido a que la ejecución fue realizada intencionalmente dentro del laboratorio para validar el funcionamiento de DET-002.

**Habilidades aplicadas:** Detection Engineering, PowerShell analysis, Event ID 4688, CommandLine analysis, KQL, Analytics Rules, Entity Mapping, MITRE ATT&CK, alert triage e incident investigation.

<p align="center">
<a href="detecciones/DET-002-powershell-sospechoso/README.md">
<img src="https://img.shields.io/badge/VER_Deteccion_DET--002-00FF41?style=for-the-badge&logo=microsoftsentinel&logoColor=black&labelColor=000000" />
</a>
</p>

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
| Análisis de PowerShell mediante CommandLine | Completado |
| Detección de indicadores sospechosos de PowerShell | Completado |
| MITRE ATT&CK — PowerShell T1059.001 | Completado |
| Integración de Sysmon → Sentinel | Completado |
| Sysmon Event ID 1 — Process Create | Completado |
| Sysmon Event ID 3 — Network Connection | Completado |
| Investigación de procesos y conexiones con Sysmon | Próxima etapa |
| Herramientas Python | Pendiente |

---

# Estructura del proyecto

```text
SOC-Sentinel-Lab/
│
├── README.md
│
├── configuracion/
│   ├── Configuración del entorno Microsoft Sentinel
│   └── SYS-001-integracion-sysmon-sentinel/
│       ├── README.md
│       └── evidencias-sys-001/
│
├── Investigaciones/
│   ├── INC-001-analisis-autenticacion/
│   └── INC-002-analisis-creacion-procesos/
│
├── detecciones/
│   ├── DET-001-multiples-intentos-fallidos/
│   └── DET-002-powershell-sospechoso/
│
└── herramientas-python/
    └── Próximamente
```

---

## Próximas etapas

El laboratorio continuará incorporando nuevas capacidades de análisis y detección, incluyendo:

- INC-003 — Investigación de procesos y conexiones de red con Sysmon.
- Correlación de Sysmon Event ID 1 y Event ID 3 mediante ProcessGuid/ProcessId.
- Reconstrucción de process trees más complejos.
- Desarrollo de nuevas reglas de detección en Microsoft Sentinel.
- Desarrollo de DET-003 utilizando telemetría de Sysmon.
- Correlación entre diferentes fuentes de telemetría.
- Ampliación del mapeo de actividad a MITRE ATT&CK.
- Desarrollo de herramientas Python para apoyar investigaciones SOC.
