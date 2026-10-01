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
- Correlacionar procesos con conexiones de red mediante Sysmon.
- Investigar creación de archivos mediante Sysmon.
- Correlacionar procesos con archivos utilizando ProcessGuid.
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
              ├── Event ID 1  — Process Create
              ├── Event ID 3  — Network Connection
              └── Event ID 11 — File Create
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

Integración de Sysmon como fuente de telemetría del endpoint Windows hacia Microsoft Sentinel mediante Azure Arc, Azure Monitor Agent y una Data Collection Rule. Se configuró la recopilación inicial de **Event ID 1 — Process Create** y **Event ID 3 — Network Connection**, validando posteriormente su llegada al Log Analytics Workspace y Microsoft Sentinel. Durante el proceso también se diagnosticaron y resolvieron problemas relacionados con la configuración y autenticación de Azure Monitor Agent.

<p align="center">
<a href="configuracion/SYS-001-integracion-sysmon-sentinel/README.md">
<img src="https://img.shields.io/badge/VER_CONFIGURACIÓN_SYS--001-00FF41?style=for-the-badge&logo=microsoftsentinel&logoColor=black&labelColor=000000" />
</a>
</p>

---

## SYS-002 — Ampliación de Sysmon con Event ID 11 File Create

Ampliación de la Data Collection Rule de Sysmon para incorporar **Event ID 11 — File Create** y obtener visibilidad sobre archivos creados en el endpoint. Se validó el evento primero de forma local y posteriormente en Microsoft Sentinel. Durante la implementación se identificó nuevamente un problema `TokenExpired` en Azure Monitor Agent, se recuperó la configuración de la DCR y finalmente se confirmó la ingestión correcta de la nueva telemetría.

<p align="center">
<a href="configuracion/SYS-002-ampliacion-sysmon-filecreate/README.md">
<img src="https://img.shields.io/badge/VER_CONFIGURACIÓN_SYS--002-00FF41?style=for-the-badge&logo=microsoftsentinel&logoColor=black&labelColor=000000" />
</a>
</p>

---

# Investigaciones

## INC-001 — Análisis de múltiples intentos fallidos de autenticación

Investigación de eventos de autenticación de Windows mediante **Event ID 4625 y 4624**. Se analizaron múltiples intentos fallidos de inicio de sesión realizados en un período corto y posteriormente se correlacionaron con una autenticación exitosa. La investigación permitió practicar análisis temporal, campos de autenticación, consultas KQL y el proceso de triage utilizado por un analista SOC.

<p align="center">
<a href="Investigaciones/INC-001-analisis-autenticacion/Proceso.md">
<img src="https://img.shields.io/badge/VER_INVESTIGACIÓN_INC--001-00FF41?style=for-the-badge&logo=microsoftsentinel&logoColor=black&labelColor=000000" />
</a>
</p>

---

## INC-002 — Análisis de creación y relación de procesos

Investigación de eventos **4688 — Process Creation** para analizar ejecuciones de PowerShell y Notepad y reconstruir relaciones entre procesos padre e hijo. Se utilizaron identificadores de proceso, información de `CommandLine` y consultas KQL para comprender cómo un analista puede reconstruir una cadena de ejecución y determinar el origen de un proceso observado en el endpoint.

<p align="center">
<a href="Investigaciones/INC-002-analisis-creacion-procesos/investigacion.md">
<img src="https://img.shields.io/badge/VER_INVESTIGACIÓN_INC--002-00FF41?style=for-the-badge&logo=microsoftsentinel&logoColor=black&labelColor=000000" />
</a>
</p>

---

## INC-003 — Investigación de procesos y conexiones de red con Sysmon

Investigación utilizando **Sysmon Event ID 1 y Event ID 3** para relacionar la creación de un proceso PowerShell con una conexión de red realizada por la misma instancia. Mediante `ProcessGuid` y KQL `join` se correlacionaron datos del proceso, línea de comandos, protocolo, dirección IP y puerto de destino, permitiendo reconstruir la relación entre ejecución y actividad de red.

<p align="center">
<a href="Investigaciones/INC-003-procesos-conexiones-sysmon/README.md">
<img src="https://img.shields.io/badge/VER_INVESTIGACIÓN_INC--003-00FF41?style=for-the-badge&logo=microsoftsentinel&logoColor=black&labelColor=000000" />
</a>
</p>

---

## INC-004 — Investigación de creación de archivos con Sysmon

Investigación de **Sysmon Event ID 1 y Event ID 11** para determinar qué proceso fue responsable de crear un archivo `.ps1` en el endpoint. Se correlacionaron `ProcessGuid`, `ProcessId`, `Image`, `CommandLine` y `TargetFilename` mediante KQL, logrando relacionar una ejecución específica de PowerShell con el archivo generado y construyendo una línea temporal de la actividad.

<p align="center">
<a href="Investigaciones/INC-004-creacion-archivos-sysmon/README.md">
<img src="https://img.shields.io/badge/VER_INVESTIGACIÓN_INC--004-00FF41?style=for-the-badge&logo=microsoftsentinel&logoColor=black&labelColor=000000" />
</a>
</p>

---

# Detecciones

## DET-001 — Múltiples intentos fallidos de inicio de sesión

Regla analítica desarrollada en Microsoft Sentinel para detectar cuentas con **3 o más intentos fallidos de autenticación dentro de una ventana de 5 minutos** utilizando Event ID 4625. La detección fue validada mediante una prueba controlada que generó una alerta y un incidente, permitiendo realizar posteriormente el proceso de investigación, clasificación y cierre.

<p align="center">
<a href="detecciones/DET-001-multiples-intentos-fallidos/README.md">
<img src="https://img.shields.io/badge/VER_Deteccion_DET--001-00FF41?style=for-the-badge&logo=microsoftsentinel&logoColor=black&labelColor=000000" />
</a>
</p>

---

## DET-002 — Ejecución sospechosa de PowerShell

Regla analítica orientada a identificar ejecuciones de PowerShell que contienen indicadores relevantes dentro de `CommandLine`, como `-ExecutionPolicy Bypass`, `-EncodedCommand`, `Invoke-WebRequest` o `IEX`. La detección utiliza Event ID 4688, fue asociada con **MITRE ATT&CK T1059.001 — PowerShell** y se validó mediante una prueba controlada que generó una alerta e incidente en Sentinel.

<p align="center">
<a href="detecciones/DET-002-powershell-sospechoso/README.md">
<img src="https://img.shields.io/badge/VER_Deteccion_DET--002-00FF41?style=for-the-badge&logo=microsoftsentinel&logoColor=black&labelColor=000000" />
</a>
</p>

---

## DET-003 — PowerShell con actividad de red correlacionada mediante Sysmon

Regla analítica que correlaciona **Sysmon Event ID 1 y Event ID 3** para detectar procesos PowerShell que presentan actividad de red asociada. La detección utiliza `ProcessGuid` para relacionar el proceso con la conexión correspondiente y permite analizar `CommandLine`, protocolo, dirección IP y puerto de destino. La regla fue validada mediante `Test-NetConnection`, generando correctamente una alerta y un incidente.

<p align="center">
<a href="detecciones/DET-003-powershell-actividad-red/README.md">
<img src="https://img.shields.io/badge/VER_Deteccion_DET--003-00FF41?style=for-the-badge&logo=microsoftsentinel&logoColor=black&labelColor=000000" />
</a>
</p>

---

## DET-004 — PowerShell creando archivos PS1 en directorios temporales

Regla analítica desarrollada para identificar procesos PowerShell que crean archivos `.ps1` dentro de directorios temporales. La detección correlaciona **Sysmon Event ID 1 y Event ID 11 mediante ProcessGuid**, combinando información del proceso, línea de comandos y archivo creado. La regla fue validada mediante una actividad controlada que generó correctamente una alerta e incidente, seguido de su investigación, clasificación y resolución.

<p align="center">
<a href="detecciones/DET-004-powershell-filecreate-temp/README.md">
<img src="https://img.shields.io/badge/VER_Deteccion_DET--004-00FF41?style=for-the-badge&logo=microsoftsentinel&logoColor=black&labelColor=000000" />
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
| Sysmon Event ID 11 — File Create | Completado |
| SYS-002 — Ampliación de telemetría Sysmon | Completado |
| Investigación de procesos y conexiones con Sysmon | Completado |
| Correlación Event ID 1 ↔ Event ID 3 mediante ProcessGuid | Completado |
| DET-003 — PowerShell con actividad de red mediante Sysmon | Completado |
| Correlación de proceso y red mediante KQL `join` | Completado |
| Investigación y triage de incidente DET-003 | Completado |
| INC-004 — Investigación de creación de archivos con Sysmon | Completado |
| Correlación Event ID 1 ↔ Event ID 11 mediante ProcessGuid | Completado |
| Análisis de File Create mediante PowerShell | Completado |
| DET-004 — PowerShell creando archivos PS1 en directorios temporales | Completado |
| Investigación y triage de incidente DET-004 | Completado |
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
│   │
│   ├── SYS-001-integracion-sysmon-sentinel/
│   │   ├── README.md
│   │   └── evidencias-sys-001/
│   │
│   └── SYS-002-ampliacion-sysmon-filecreate/
│       ├── README.md
│       └── evidencias-sys-002/
│
├── Investigaciones/
│   ├── INC-001-analisis-autenticacion/
│   ├── INC-002-analisis-creacion-procesos/
│   │
│   ├── INC-003-procesos-conexiones-sysmon/
│   │   ├── README.md
│   │   └── evidencias-inc-003/
│   │
│   └── INC-004-creacion-archivos-sysmon/
│       ├── README.md
│       └── evidencias-inc-004/
│
├── detecciones/
│   ├── DET-001-multiples-intentos-fallidos/
│   ├── DET-002-powershell-sospechoso/
│   │
│   ├── DET-003-powershell-actividad-red/
│   │   ├── README.md
│   │   └── evidencias-det-003/
│   │
│   └── DET-004-powershell-filecreate-temp/
│       ├── README.md
│       └── evidencias-det-004/
│
└── herramientas-python/
    └── Próximamente
```
