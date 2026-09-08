# INC-001 — Análisis de múltiples intentos fallidos de autenticación

## 1. Resumen

Durante el análisis de eventos de autenticación recopilados en Microsoft Sentinel, se identificaron múltiples intentos fallidos de inicio de sesión asociados con la misma cuenta de usuario.

El objetivo de la investigación fue analizar los eventos, establecer una línea temporal y correlacionar los intentos fallidos con eventos posteriores para determinar si la actividad podía representar un intento de acceso no autorizado.

---

## 2. Fuente de datos

La investigación se realizó utilizando los eventos de seguridad de Windows recopilados por Microsoft Sentinel.

| Campo | Valor |
|---|---|
| SIEM | Microsoft Sentinel |
| Fuente de datos | Windows Security Events |
| Tabla | `SecurityEvent` |
| Eventos principales | `4625` y `4624` |

### Eventos utilizados

- `4625` — Inicio de sesión fallido.
- `4624` — Inicio de sesión exitoso.

---

## 3. Identificación de intentos fallidos

La investigación comenzó buscando eventos `4625` en Microsoft Sentinel.

Se utilizó la siguiente consulta KQL:

```kusto
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Computer, Account, IpAddress, LogonType, Activity
| order by TimeGenerated asc
```

La consulta permitió analizar los siguientes campos:

- `TimeGenerated`: momento en que el evento fue registrado.
- `Computer`: endpoint que generó el evento.
- `Account`: cuenta involucrada en el intento de autenticación.
- `IpAddress`: dirección IP registrada en el evento.
- `LogonType`: tipo de inicio de sesión.
- `Activity`: descripción de la actividad registrada.

Se identificaron tres eventos `4625` asociados con la misma cuenta.

### Evidencia — Intentos fallidos de autenticación

![Intentos fallidos Event ID 4625](Investigaciones/INC-001-analisis-autenticacion/evidencias-inc-001/01-intentos-fallidos-4625.png)

---

## 4. Delimitación temporal de la investigación

Durante el desarrollo del laboratorio se generaron posteriormente otros eventos de autenticación.

Para evitar mezclar esos eventos con la actividad correspondiente a esta investigación, se delimitó el análisis al intervalo temporal específico del incidente.

```kusto
SecurityEvent
| where EventID == 4625
| where TimeGenerated between (
    datetime(2026-09-08 16:56:30) ..
    datetime(2026-09-08 16:56:45)
)
| summarize IntentosFallidos=count(),
            PrimerIntento=min(TimeGenerated),
            UltimoIntento=max(TimeGenerated)
    by Account, Computer, IpAddress, LogonType
| order by IntentosFallidos desc
```

La consulta permitió agrupar los eventos utilizando la cuenta, endpoint, dirección IP y tipo de inicio de sesión.

---

## 5. Análisis de los intentos fallidos

El resultado mostró:

| Campo | Resultado |
|---|---|
| Intentos fallidos | 3 |
| Primer intento | 16:56:36.335 UTC |
| Último intento | 16:56:40.563 UTC |
| Dirección IP | `127.0.0.1` |
| LogonType | `2` |

Los tres intentos fallidos ocurrieron en aproximadamente cuatro segundos.

El valor `127.0.0.1` corresponde a la dirección de loopback o localhost.

El `LogonType 2` corresponde a un inicio de sesión interactivo/local en Windows.

### Evidencia — Agrupación de intentos fallidos

![Resumen de intentos fallidos](evidencias/02-resumen-intentos-fallidos.png)

---

## 6. Correlación con autenticación exitosa

La presencia de tres eventos `4625` no es suficiente por sí sola para determinar que ocurrió un ataque.

Por este motivo, la investigación continuó buscando eventos de autenticación exitosa cercanos temporalmente.

Se correlacionaron los eventos `4624` y `4625` mediante la siguiente consulta:

```kusto
SecurityEvent
| where EventID in (4624, 4625)
| where TimeGenerated between (
    datetime(2026-09-08 16:56:30) ..
    datetime(2026-09-08 16:56:50)
)
| project TimeGenerated, EventID, Account, Computer, IpAddress, LogonType, Activity
| order by TimeGenerated asc
```

Se obtuvo la siguiente secuencia:

| Hora UTC | Event ID | Resultado |
|---|---:|---|
| 16:56:36.335 | 4625 | Inicio de sesión fallido |
| 16:56:38.547 | 4625 | Inicio de sesión fallido |
| 16:56:40.563 | 4625 | Inicio de sesión fallido |
| 16:56:44.333 | 4624 | Inicio de sesión exitoso |

El evento `4624` ocurrió aproximadamente **3.77 segundos después del último evento 4625**.

### Evidencia — Correlación de eventos

![Correlación entre eventos 4625 y 4624](evidencias/03-correlacion-4625-4624.png)

---

## 7. Análisis de la actividad

La correlación mostró el siguiente patrón:

```text
4625 — Fallido
       ↓
4625 — Fallido
       ↓
4625 — Fallido
       ↓
4624 — Exitoso
```

Los cuatro eventos presentan características consistentes:

- Misma cuenta de usuario.
- Mismo endpoint.
- Dirección IP `127.0.0.1`.
- `LogonType 2`.
- Intervalo temporal muy reducido.

El `LogonType 2` indica una autenticación interactiva/local y la dirección `127.0.0.1` es consistente con actividad local en el endpoint.

El patrón observado es compatible con un usuario introduciendo incorrectamente sus credenciales varias veces antes de autenticarse correctamente.

Aunque múltiples fallos seguidos de una autenticación exitosa pueden ser relevantes durante una investigación de seguridad, la evidencia disponible en este caso no demuestra por sí sola un ataque de fuerza bruta ni un compromiso de cuenta.

---

## 8. Evaluación del incidente

| Categoría | Evaluación |
|---|---|
| Clasificación | Benigno / Falso positivo |
| Severidad | Baja |
| Acceso remoto identificado | No |
| Compromiso de cuenta identificado | No |
| Escalamiento | No requerido |

---

## 9. Conclusión

La investigación identificó tres intentos fallidos de autenticación seguidos de un inicio de sesión exitoso aproximadamente cuatro segundos después.

La correlación de `TimeGenerated`, `Account`, `Computer`, `IpAddress` y `LogonType` permitió reconstruir la secuencia de autenticación y proporcionar contexto adicional a los eventos `4625`.

Con base en la evidencia disponible, la actividad es consistente con errores de autenticación de un usuario local antes de introducir correctamente sus credenciales.

Por este motivo, el caso fue clasificado como **actividad benigna / falso positivo**, sin evidencia suficiente para confirmar un intento de acceso no autorizado.

---

## 10. Habilidades aplicadas

Durante esta investigación se aplicaron las siguientes habilidades:

- Análisis de Windows Security Events.
- Investigación de Event ID `4625`.
- Investigación de Event ID `4624`.
- Consultas y filtrado mediante KQL.
- Delimitación temporal de eventos.
- Agrupación de eventos mediante `summarize`.
- Correlación de eventos de autenticación.
- Construcción de una línea temporal.
- Análisis de `LogonType`.
- Triage básico de actividad de autenticación.
- Clasificación y documentación de un incidente SOC.

---

## 11. Próximo paso

La siguiente fase del laboratorio consistirá en transformar el análisis manual de eventos de autenticación en una detección automatizada mediante Microsoft Sentinel.

El objetivo será desarrollar una consulta KQL capaz de identificar múltiples intentos fallidos de autenticación y posteriormente utilizarla como base para una regla analítica.
