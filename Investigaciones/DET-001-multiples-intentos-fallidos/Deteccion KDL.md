// DET-001 - Múltiples intentos fallidos de inicio de sesión
//
// Objetivo:
// Detectar cuentas que presenten 3 o más intentos fallidos de
// autenticación (Event ID 4625) dentro de una ventana de 5 minutos.
//
// Fuente de datos:
// Windows Security Events - SecurityEvent
//
// Nota:
// Esta detección identifica un patrón que requiere investigación.
// El resultado no implica por sí solo que exista actividad maliciosa.

SecurityEvent

// Filtra únicamente los eventos de autenticación fallida de Windows.
| where EventID == 4625

// Agrupa los eventos por cuenta, equipo, dirección IP,
// tipo de inicio de sesión y bloques de tiempo de 5 minutos.
// count() calcula la cantidad de intentos fallidos de cada grupo.
| summarize IntentosFallidos=count()
    by Account, Computer, IpAddress, LogonType, bin(TimeGenerated, 5m)

// Conserva únicamente los grupos que registraron
// 3 o más intentos fallidos.
| where IntentosFallidos >= 3

// Ordena los resultados desde la mayor cantidad
// de intentos fallidos hasta la menor.
| order by IntentosFallidos desc
