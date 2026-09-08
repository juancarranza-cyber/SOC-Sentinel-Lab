# Configuración del laboratorio con Microsoft Sentinel

## 1. Objetivo

El objetivo de esta fase fue implementar un entorno de laboratorio SOC utilizando Microsoft Sentinel para centralizar y analizar eventos de seguridad generados por un endpoint Windows.

## 2. Recursos utilizados

Para la implementación se utilizaron los siguientes componentes:

- Microsoft Azure
- Microsoft Sentinel
- Log Analytics Workspace
- Azure Arc
- Azure Monitor Agent (AMA)
- Data Collection Rule (DCR)
- Windows Security Events
- Endpoint Windows 10

## 3. Arquitectura del laboratorio

El flujo de recopilación de eventos implementado es el siguiente:

Windows 10 Endpoint  
↓  
Azure Arc  
↓  
Azure Monitor Agent (AMA)  
↓  
Data Collection Rule (DCR)  
↓  
Log Analytics Workspace  
↓  
Microsoft Sentinel

## 4. Recursos de Azure

Se configuraron los siguientes recursos:

- Resource Group: `rg-soc-lab`
- Log Analytics Workspace: `law-soc-lab`
- Data Collection Rule: `dcr-windows-security-soc-lab`

## 5. Integración del endpoint

El equipo Windows utilizado para el laboratorio fue conectado a Microsoft Azure mediante Azure Arc.

Posteriormente, Azure Monitor Agent fue utilizado para recopilar los eventos de seguridad del sistema y enviarlos al Log Analytics Workspace asociado con Microsoft Sentinel.

## 6. Eventos recopilados

Para limitar la cantidad de información enviada al SIEM y mantener el laboratorio enfocado en eventos relevantes para investigaciones SOC, se configuró inicialmente la recopilación de los siguientes Event ID:

| Event ID | Descripción |
|---|---|
| 4624 | Inicio de sesión exitoso |
| 4625 | Inicio de sesión fallido |
| 4634 | Cierre de sesión |
| 4648 | Inicio de sesión utilizando credenciales explícitas |
| 4688 | Creación de un nuevo proceso |

La recopilación se configuró mediante una Data Collection Rule utilizando un filtro XPath personalizado.

## 7. Validación de la ingesta

Después de completar la configuración, se verificó en Microsoft Sentinel que los eventos de Windows estuvieran siendo recibidos correctamente.

La validación se realizó mediante consultas KQL sobre la tabla `SecurityEvent`.

Esto confirmó el funcionamiento del flujo:

Windows → Azure Arc → AMA → Log Analytics → Microsoft Sentinel
