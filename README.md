# Laboratorio SOC con Microsoft Sentinel

## Descripción

Laboratorio práctico de ciberseguridad orientado a simular las actividades de un analista SOC utilizando Microsoft Sentinel.

El proyecto incluye la recopilación y análisis de eventos de seguridad de Windows, investigaciones mediante KQL, creación de detecciones y análisis de incidentes de seguridad.

## Tecnologías utilizadas

- Microsoft Sentinel
- Microsoft Azure
- Azure Arc
- Azure Monitor Agent (AMA)
- Log Analytics Workspace
- Windows Security Events
- KQL (Kusto Query Language)
- Windows 10

## Objetivos del laboratorio

- Centralizar eventos de seguridad de Windows en Microsoft Sentinel.
- Analizar eventos mediante consultas KQL.
- Investigar intentos de autenticación.
- Correlacionar diferentes eventos de seguridad.
- Crear reglas de detección.
- Generar y analizar alertas e incidentes.
- Documentar investigaciones siguiendo un flujo de trabajo SOC.
- Relacionar actividad sospechosa con MITRE ATT&CK.
- Utilizar Python para apoyar tareas de análisis y automatización.

## Arquitectura

Windows Endpoint  
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

