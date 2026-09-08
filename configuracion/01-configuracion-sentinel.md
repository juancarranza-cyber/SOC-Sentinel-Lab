# Configuración del laboratorio SOC con Microsoft Sentinel

## 1. Objetivo

El objetivo de esta fase fue implementar un laboratorio SOC utilizando **Microsoft Sentinel** para centralizar, recopilar y analizar eventos de seguridad generados por un endpoint Windows.

El entorno fue diseñado para practicar actividades relacionadas con monitoreo de seguridad, análisis de logs, investigación de eventos y detección de amenazas utilizando herramientas y tecnologías empleadas en entornos SOC.

---

## 2. Tecnologías utilizadas

Para la implementación del laboratorio se utilizaron los siguientes componentes:

- Microsoft Azure
- Microsoft Sentinel
- Log Analytics Workspace
- Azure Arc
- Azure Monitor Agent (AMA)
- Data Collection Rule (DCR)
- Windows Security Events
- KQL (Kusto Query Language)
- Windows 10

---

## 3. Arquitectura del laboratorio

El flujo de recopilación de eventos implementado es el siguiente:

```text
Windows 10 Endpoint
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
```

El endpoint Windows genera eventos de seguridad que son recopilados mediante **Azure Monitor Agent**.

La **Data Collection Rule** determina qué eventos deben ser enviados al **Log Analytics Workspace**, donde posteriormente pueden ser consultados y analizados desde **Microsoft Sentinel**.

---

## 4. Configuración de Log Analytics Workspace

Se creó un **Log Analytics Workspace** para centralizar la telemetría de seguridad recopilada durante el laboratorio.

### Recursos utilizados

| Recurso | Configuración |
|---|---|
| Resource Group | `rg-soc-lab` |
| Log Analytics Workspace | `law-soc-lab` |
| Región | East US |
| Modelo de ingesta | Pago por uso |

El workspace `law-soc-lab` funciona como repositorio central de los eventos enviados desde el endpoint Windows.

### Evidencia — Log Analytics Workspace

La siguiente captura muestra el Log Analytics Workspace utilizado para el laboratorio.

![Log Analytics Workspace](configuracion/evidencias-configuracion/01-log-analytics-workspace.png).

---

## 5. Habilitación de Microsoft Sentinel

Microsoft Sentinel fue habilitado sobre el Log Analytics Workspace `law-soc-lab`.

Esto permite utilizar el workspace como parte de una plataforma SIEM para realizar consultas, investigaciones y posteriormente crear reglas de detección y alertas de seguridad.

### Evidencia — Microsoft Sentinel

La siguiente captura muestra Microsoft Sentinel asociado al workspace `law-soc-lab`.

![Microsoft Sentinel](evidencias/02-microsoft-sentinel.png)

---

## 6. Instalación de Windows Security Events

Desde el **Content Hub** de Microsoft Sentinel se instaló la solución:

`Windows Security Events`

Esta solución proporciona los componentes necesarios para trabajar con eventos de seguridad generados por sistemas Windows.

### Evidencia — Windows Security Events

La solución aparece correctamente instalada en Microsoft Sentinel.

![Windows Security Events](evidencias/03-windows-security-events.png)

---

## 7. Integración del endpoint mediante Azure Arc

Debido a que el endpoint utilizado para el laboratorio es un equipo Windows externo a Azure, se utilizó **Azure Arc** para conectarlo con el entorno de Azure.

Una vez completada la integración, el endpoint apareció con estado:

`Connected`

Esto permitió utilizar Azure Monitor Agent para recopilar telemetría desde el sistema Windows.

### Evidencia — Azure Arc

La siguiente captura demuestra que el endpoint Windows se encuentra conectado mediante Azure Arc.

![Endpoint conectado mediante Azure Arc](evidencias/04-azure-arc-endpoint.png)

---

## 8. Configuración de Data Collection Rule

Para controlar qué información del endpoint debía enviarse al Log Analytics Workspace se creó una **Data Collection Rule (DCR)**.

La regla utilizada fue:

`dcr-windows-security-soc-lab`

La DCR fue asociada con el endpoint Windows conectado mediante Azure Arc.

### Evidencia — Data Collection Rule

La siguiente captura muestra la DCR utilizada para recopilar eventos de seguridad.

![Data Collection Rule](evidencias/05-data-collection-rule.png)

---

## 9. Selección de eventos de seguridad

En lugar de recopilar todos los eventos disponibles del registro de seguridad de Windows, se configuró una recopilación selectiva.

Esto permite mantener el laboratorio enfocado en eventos relevantes para investigaciones SOC y reducir la ingesta de información innecesaria.

Los eventos seleccionados inicialmente fueron:

| Event ID | Descripción |
|---:|---|
| 4624 | Inicio de sesión exitoso |
| 4625 | Inicio de sesión fallido |
| 4634 | Cierre de sesión |
| 4648 | Inicio de sesión utilizando credenciales explícitas |
| 4688 | Creación de un nuevo proceso |

---

## 10. Filtro XPath

La selección de eventos se realizó mediante un filtro XPath personalizado dentro de la Data Collection Rule.

```text
Security!*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4648 or EventID=4688)]]
```

Este filtro indica que únicamente se deben recopilar los eventos especificados del registro `Security` de Windows.

### Evidencia — Configuración del filtro

La siguiente captura muestra el filtro configurado en la DCR.

![Filtro XPath de eventos de seguridad](evidencias/06-filtro-eventos-dcr.png)

---

## 11. Habilitación de auditoría de creación de procesos

Durante la validación inicial se observó que los eventos `4688` no estaban siendo generados por el endpoint.

El Event ID `4688` corresponde a la creación de un nuevo proceso en Windows.

Para habilitar esta auditoría se utilizó `auditpol` desde PowerShell con privilegios administrativos.

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

Posteriormente se generaron nuevos procesos en el endpoint para verificar que Windows comenzara a registrar eventos `4688`.

La recepción posterior de estos eventos en Microsoft Sentinel confirmó que la auditoría de creación de procesos estaba funcionando correctamente.

---

## 12. Validación de la ingesta

Una vez configurado el flujo de recopilación, se verificó que los eventos estuvieran llegando correctamente a Microsoft Sentinel.

Para realizar la validación se utilizó la siguiente consulta KQL:

```kusto
SecurityEvent
| where EventID in (4624, 4625, 4634, 4648, 4688)
| summarize Cantidad=count(), UltimoEvento=max(TimeGenerated) by EventID
| order by EventID asc
```

La consulta permitió comprobar la presencia de los cinco Event ID configurados:

- `4624`
- `4625`
- `4634`
- `4648`
- `4688`

### Evidencia — Eventos recibidos en Microsoft Sentinel

La siguiente captura muestra la consulta KQL ejecutada y los eventos recibidos.

![Validación de ingesta en Microsoft Sentinel](evidencias/07-validacion-ingesta-securityevent.png)

---

## 13. Resultado de la implementación

La validación confirmó el funcionamiento del flujo completo de recopilación:

```text
Windows Security Events
        │
        ▼
Azure Arc
        │
        ▼
Azure Monitor Agent
        │
        ▼
Data Collection Rule
        │
        ▼
Log Analytics Workspace
        │
        ▼
Microsoft Sentinel
        │
        ▼
SecurityEvent
```

Microsoft Sentinel recibe correctamente los eventos de seguridad seleccionados desde el endpoint Windows.

El laboratorio queda preparado para realizar investigaciones SOC utilizando los datos almacenados en la tabla `SecurityEvent`.

---

## 14. Próxima fase

Con la infraestructura y la ingesta de eventos funcionando correctamente, la siguiente fase consiste en utilizar la telemetría recopilada para realizar investigaciones de seguridad.

La primera investigación del laboratorio corresponde a:

**INC-001 — Análisis de múltiples intentos fallidos de autenticación seguidos de un inicio de sesión exitoso.**

En esta investigación se utilizarán principalmente los eventos:

- `4625` — Inicio de sesión fallido
- `4624` — Inicio de sesión exitoso

El objetivo será analizar y correlacionar los eventos mediante KQL para determinar si la actividad observada representa comportamiento legítimo o potencialmente malicioso.
