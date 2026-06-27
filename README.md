# Monitor de Trafico de Red

**Autor / Desarrollador:** Leonardo Jiménez Martínez

Prototipo de escritorio (Windows) para vigilar el trafico de red de tu
equipo: que interfaces estan activas, que programas estan usando la
red, quien esta conectado a tu red local (no solo lo que habla con tu
PC), si hay senales de un ataque (escaneo de puertos, fuerza bruta), y
un registro historico de a quien le estas enviando datos, cuando y
desde que parte del mundo se conecta.

Construido en tres modulos con responsabilidades separadas (Requisitos
→ Flujo → Generador de Codigo/GUI): cada uno produce un dato concreto
que el siguiente consume, y un modulo puede activar o desactivar pasos
del siguiente segun unas banderas de configuracion. Ver la seccion
[Arquitectura](#arquitectura) para el detalle de que hace cada parte.

## Que hace, en una frase por funcion

- **Trafico por interfaz**: velocidad de subida/bajada en Mbps y bytes
  totales, por cada tarjeta de red.
- **Conexiones activas**: cada conexion TCP/UDP del equipo, con PID,
  proceso, direcciones, estado y **tipo de programa** (navegador,
  mensajeria, sistema, etc.).
- **Otros dispositivos que se conectaron a este equipo**: detecta y
  lista equipos distintos al tuyo (IPs privadas de tu LAN) que han
  establecido conexion con procesos de esta maquina.
- **Quien esta en mi red (escaneo completo)**: a diferencia del punto
  anterior, esto lista **todo** lo que responde en tu red local en
  este momento, hayan hablado con tu PC o no -- util para detectar a
  alguien ajeno usando tu Internet. Adivina fabricante y tipo de
  dispositivo (telefono, PC, router, IoT) por su MAC y nombre de host.
- **Posibles ataques**: heuristicas de escaneo de puertos y fuerza
  bruta contra servicios que tienes expuestos, con la IP de origen,
  ubicacion y el proceso local afectado.
- **Quien extrae tus datos**: historial de a que sistemas externos
  (Internet o tu LAN) se les ha enviado trafico: quien (proceso),
  cuando (inicio/fin), desde donde (ciudad/pais/ISP), que protocolo y
  un volumen aproximado en MB. Se guarda en CSV de forma permanente.
- **Geolocalizacion**: ubicacion aproximada de tu propia salida a
  Internet y de cada IP remota publica con la que te conectas.
- **Alertas visuales**: un indicador parpadeante en la barra superior
  (visible en cualquier pestaña) y una ventana emergente que aparece
  sola cuando hay trafico por encima de un umbral, un dispositivo
  nuevo en tu red, o un posible ataque -- con botones para actuar o
  ignorar.
- **Cerrar procesos sospechosos** y **bloquear dispositivos/IPs en
  este equipo**: si ves un programa o dispositivo que no reconoces,
  puedes actuar desde la propia interfaz.
- **No inicia el monitoreo solo.** Al abrir la app solo aparece una
  ventana de control; tu decides cuando activar y detener todo lo
  anterior.
- Permite crear un acceso directo en el Escritorio para abrir el
  prototipo cuando quieras, sin terminal.

## Arquitectura

### Los 3 modulos principales

Se llaman "agentes" como metafora del diseño original (cada uno con una
responsabilidad fija), pero son funciones y clases Python normales que
se ejecutan una sola vez, en orden, al abrir la ventana.

| Modulo | Archivo | Rol |
|---|---|---|
| 1. Definidor de Requisitos | [requirements_agent.py](requirements_agent.py) | Unica fuente de verdad de los criterios de monitoreo (intervalos, umbrales, que funciones estan activas). Los fija por defecto, sin preguntar nada. |
| 2. Arquitecto de Flujo | [flow_architect.py](flow_architect.py) | Traduce esos criterios en una lista ordenada de pasos a ejecutar. Si un criterio desactiva una funcion, quita el paso correspondiente de la lista — una condicional simple, no una decision autonoma. |
| 3. Generador de Codigo | [app.py](app.py) | Construye la interfaz grafica (Tkinter) que implementa esos pasos. Es el unico punto de contacto con el usuario; no decide nada por su cuenta, solo presenta y deja accionar lo que los otros dos ya definieron. |

### Para que sirve separarlo asi (la intencion, no solo la forma)

La razon es practica, no conceptual: separar "que se monitorea" de
"como se ejecuta" y de "como se ve", para que cambiar algo implique
tocar **un solo archivo** y no romper el resto.

- **Cambiar un criterio sin tocar el motor ni la interfaz.** Si quieres
  otro umbral de alerta o desactivar la geolocalizacion, editas solo
  `requirements_agent.py`. No hace falta entender Tkinter ni como se
  leen las conexiones — un valor, un archivo.
- **Prender o apagar una funcion entera desde un solo lugar.** Cada
  funcion grande (clasificar procesos, detectar otros dispositivos,
  registrar extraccion de datos, detectar ataques) se activa con una
  bandera en `requirements_agent.py`. Si alguna estorba o falla, se
  apaga ahi mismo y `flow_architect.py` deja de ejecutarla en todos
  lados — sin buscar y comentar codigo disperso en `monitor_core.py` o
  `app.py`.
- **Agregar funciones nuevas sin reescribir las viejas.** Asi crecio
  este proyecto: trafico por interfaz, luego conexiones, categorias,
  dispositivos LAN, geolocalizacion, egress, alertas visuales,
  deteccion de ataques, escaneo completo de red — cada pieza se sumo
  sin tocar ni romper las anteriores, porque estan separadas.
- **Probar la logica sin abrir la ventana.** El motor (`monitor_core.py`)
  se puede probar llamandolo directo desde una terminal, sin lanzar la
  GUI. Si todo estuviera mezclado en un solo archivo con la interfaz,
  no se podria verificar nada sin abrir la ventana cada vez.

### Modulos de soporte (el motor, sin interfaz)

| Archivo | Para que sirve |
|---|---|
| [monitor_core.py](monitor_core.py) | El motor de datos. Ejecuta cada paso del workflow (leer contadores, calcular tasas, listar conexiones, clasificar, detectar dispositivos, registrar extraccion de datos, detectar ataques, evaluar alertas, guardar logs) usando `psutil`. No sabe nada de interfaces graficas. |
| [process_classifier.py](process_classifier.py) | Heuristica que asigna una categoria (Navegador web, Sistema operativo, Mensajeria, etc.) a un proceso segun su nombre, para el resumen "Programas por tipo". |
| [geo_lookup.py](geo_lookup.py) | Resuelve ciudad/region/pais/ISP de una IP publica usando el servicio gratuito `ip-api.com`. Cachea resultados y resuelve en segundo plano para no congelar la ventana. |
| [hostname_lookup.py](hostname_lookup.py) | Resuelve el nombre de host (DNS inverso) de IPs de tu red local, para identificar que dispositivo es. |
| [port_protocols.py](port_protocols.py) | Traduce un puerto remoto comun (443, 445, 3389, etc.) a una descripcion legible del tipo de trafico/protocolo. |
| [process_inspector.py](process_inspector.py) | Reune toda la informacion disponible de un PID a peticion del usuario (ruta del ejecutable, usuario, linea de comandos, proceso padre, hora de inicio) para decidir si es confiable. |
| [process_blocker.py](process_blocker.py) | Cierra (`terminate()`) los procesos que el usuario elija explicitamente desde la interfaz. Accion puntual e irreversible, nunca automatica. |
| [lan_scanner.py](lan_scanner.py) | Sondea activamente tu subred local (ping + puertos comunes para estimular ARP) y lee la tabla ARP real del sistema para listar todo lo que responde en tu red, no solo lo que hablo con esta maquina. |
| [device_identifier.py](device_identifier.py) | Adivina fabricante (tabla de prefijos MAC/OUI) y tipo de dispositivo (telefono, PC, router, IoT) combinando la MAC con pistas del nombre de host. Es una suposicion, no una certeza. |
| [known_devices.py](known_devices.py) | Lista persistente de dispositivos de tu red, identificados por MAC, marcados como Confiable / Bloqueado / Sin marcar. |
| [firewall_blocker.py](firewall_blocker.py) | Crea/elimina reglas del Firewall de Windows para bloquear una IP especifica en ESTE equipo. Requiere permisos de administrador. |
| [create_shortcut.py](create_shortcut.py) | Crea el acceso directo del Escritorio (boton de la app), usando PowerShell para generar el `.lnk`. |

Flujo de datos: `requirements_agent` → `flow_architect` → `monitor_core` (+ sus modulos de soporte) → `app` (GUI).

### Criterios por defecto (Agente 1)

- Intervalo de actualizacion: **2 segundos**
- Umbral de alerta de trafico: **50 Mbps** por interfaz (subida + bajada)
- Umbral de alerta de conexiones: **200** conexiones activas simultaneas
- Maximo de conexiones listadas: **100**
- Clasificacion de procesos por tipo: **activada**
- Deteccion de otros dispositivos en la red local: **activada**
- Registro de extraccion de datos (egress): **activado**, log en `egress_log.csv`
- Deteccion de ataques: **activada** — ventana de analisis **60s**,
  umbral de escaneo de puertos **6** puertos distintos, umbral de
  fuerza bruta **5** intentos al mismo puerto sensible, log en
  `attack_log.csv`
- Log general a archivo: **activado**, en `network_monitor_log.csv`

Para cambiar estos valores, edita los valores por defecto en
`requirements_agent.py` (clase `MonitoringRequirements`).

## Requisitos

- Python 3.9+ (probado en 3.13)
- Paquete `psutil` (instalar con `pip install -r requirements.txt`)
- Tkinter (incluido con Python en Windows)
- Conexion a Internet **opcional**: solo se usa para resolver
  geolocalizacion de IPs publicas (`ip-api.com`). Sin Internet, el
  resto del monitoreo funciona igual, esas columnas mostraran
  "No disponible".
- Permisos de administrador **opcionales**: sin ellos, todo el
  monitoreo y la deteccion funcionan igual; solo fallan (con un
  mensaje claro, no en silencio) las acciones que cierran procesos de
  otros usuarios o que crean reglas de Firewall.

## Como usarlo

### Opcion A: doble clic (recomendado)

Haz doble clic en **`Iniciar Monitor.bat`**. Se abre la ventana sin
mostrar consola.

### Opcion B: desde terminal

```
python app.py
```

### Dentro de la aplicacion

1. **Iniciar monitoreo** — empieza a leer y mostrar datos cada 2s,
   dispara la deteccion de tu propia ubicacion aproximada (una sola
   vez) y el primer escaneo de "Quien esta en mi red" (que se repite
   cada 90s mientras el monitoreo este activo).
2. **Detener** — pausa la lectura (la ventana queda abierta).
3. **Crear acceso directo en el Escritorio** — genera
   `Monitor de Trafico de Red.lnk`, para abrir el prototipo sin
   terminal cuando quieras.

Al cerrar la ventana (X), el monitoreo se detiene automaticamente.

## Las pestanas, una por una

### Resumen

- **Interfaces de red**: subida/bajada en Mbps y totales acumulados
  por tarjeta de red.
- **Programas por tipo**: cuenta de conexiones activas agrupadas por
  categoria de programa. **Clic en una fila** abre el detalle: todas
  las conexiones de ese tipo, con boton para **cerrar el/los proceso(s)
  seleccionado(s)** si no los reconoces (pide confirmacion, accion
  irreversible).
- **Alertas**: avisos cuando se supera un umbral, aparece un
  dispositivo nuevo, o se detecta un posible ataque.
- Arriba de todo, tu ubicacion aproximada de salida a Internet.

### Conexiones activas

Tabla completa de cada conexion: PID, proceso, tipo de programa,
direcciones local/remota, origen (Este equipo / Red local / Internet),
ubicacion e ISP, y estado. Incluye el switch **"Cerrar procesos
'Desconocido' detectados ahora"**, que actua de una sola vez sobre lo
que esta en pantalla en ese momento (no vigila el futuro).

### Otros dispositivos en mi red

Lista de IPs de tu red local (no este equipo, no Internet) que **se
han conectado con procesos de tu maquina**: cuantas conexiones, que
procesos locales involucran, nombre de host si se resuelve, y cuando
se vieron por primera y ultima vez.

### Quien esta en mi red

A diferencia de la pestaña anterior, esta hace un **escaneo activo de
toda tu subred** (no solo lo que hablo con tu PC): botón "Escanear red
ahora" y repeticion automatica cada 90s mientras el monitoreo este
activo. Cada dispositivo se identifica por su **MAC**, con fabricante
y tipo de dispositivo probable (telefono, PC, router, IoT) adivinados
por la MAC y el nombre de host.

Cualquier dispositivo "Sin marcar" activa el indicador de alerta y
abre una ventana emergente con tres opciones: **"Es mio, confiable"**,
**"Bloquear en mi equipo"** o **"Ignorar por ahora"**. La lista de
dispositivos marcados se guarda en `known_devices.csv` y persiste
entre sesiones.

**Limite honesto**: "Bloquear" crea una regla de Firewall de Windows
que impide que ese dispositivo se comunique con ESTE equipo — no lo
expulsa de tu WiFi/router en general, eso solo se puede hacer desde la
configuracion del router. El fabricante/tipo de dispositivo es una
suposicion razonable (tabla de prefijos MAC + nombre de host), no una
certeza: no hay forma de saber con seguridad el sistema operativo
exacto sin acceder al dispositivo.

### Posibles ataques

Detecta dos patrones clasicos contra servicios que tu equipo expone:

- **Escaneo de puertos**: la misma IP toca varios puertos distintos
  donde tu equipo esta escuchando, en poco tiempo.
- **Posible fuerza bruta**: muchos intentos repetidos contra el mismo
  puerto sensible (RDP, SSH, carpetas compartidas, bases de datos,
  VNC, etc.).

Cada deteccion muestra IP de origen, ubicacion, y el **proceso local
expuesto con su PID**, y dispara el indicador de alerta + una ventana
emergente con la opcion de **"Bloquear ahora (cerrar proceso)"** o
**"Ignorar"**. Se guarda en `attack_log.csv`.

**Limite honesto**: solo se detecta lo que realmente llega a crear una
conexion en el sistema operativo. La mayoria de escaneos de Internet
ya los bloquea el Firewall de Windows antes de llegar aqui, asi que
esto es mas util para abuso de algo que tienes expuesto (un puerto
reenviado, un servicio accesible) o ataques que ya estan dentro de tu
red local.

### Quien extrae tus datos

Historial de toda conexion saliente hacia un sistema externo
(Internet o tu LAN): inicio, ultima actividad, duracion, proceso,
tipo, destino, protocolo, origen, ubicacion/ISP y un volumen
**aproximado** en MB. Incluye el boton **"Cerrar proceso(s) de la(s)
conexion(es) seleccionada(s)"**: si no reconoces un destino, lo
seleccionas y cierras el proceso responsable.

Se guarda de forma permanente en `egress_log.csv`, asi que el
historial sobrevive aunque cierres la app.

## Alertas: como te avisan

- **Indicador parpadeante** en la barra superior (un punto que pasa de
  gris a rojo intermitente), visible en cualquier pestaña que estes
  viendo.
- **Ventana emergente automatica** (con sonido) cuando se detecta un
  posible ataque o un dispositivo nuevo en tu red, con botones para
  actuar (bloquear/cerrar) o ignorar. Cada combinacion IP+tipo o MAC
  solo avisa una vez por sesion de monitoreo, para no saturarte con la
  misma alerta cada par de segundos.
- El texto de las alertas tambien queda en la pestaña "Resumen" y en
  los logs CSV correspondientes.

## Acciones de bloqueo: que hacen y que no

- **Cerrar un proceso** (`Process.terminate()`): cierra el proceso
  completo, no solo una conexion -- si tenia otras conexiones
  legitimas, tambien se cierran. Siempre pide confirmacion con el PID
  exacto, y es irreversible.
- **Bloquear un dispositivo/IP** (regla de Firewall de Windows): solo
  evita que esa IP se comunique con ESTE equipo. No afecta al resto de
  tu red ni la expulsa del router/WiFi.
- Ambas requieren permisos de administrador para actuar sobre
  procesos/IPs que no son tuyos; sin ellos, fallan con un mensaje
  claro en vez de fallar en silencio.

## Logs generados

| Archivo | Contenido |
|---|---|
| `network_monitor_log.csv` | Una fila por interfaz en cada lectura: `timestamp, interface, upload_mbps, download_mbps, alertas`. |
| `egress_log.csv` | Una fila por cada conexion saliente finalizada: `inicio, fin, duracion_seg, pid, proceso, categoria, ip_remota, puerto, protocolo, origen, ubicacion, isp, mb_estimados`. |
| `attack_log.csv` | Una fila por cada deteccion de ataque: `timestamp, tipo, ip_origen, origen, ubicacion, isp, proceso_local, pid_local, detalle`. |
| `known_devices.csv` | Un registro por dispositivo de tu red (por MAC): etiqueta (Confiable/Bloqueado/Sin marcar), fabricante, tipo probable, ultimo hostname/IP, primera y ultima vez visto. |

**Estos cuatro archivos contienen tu historial real de red** (a que
IPs te conectaste, cuando, que programa, quien esta en tu red, posibles
ataques recibidos). Por eso estan en `.gitignore` y nunca deben
subirse a un repositorio, compartirse, ni publicarse — equivalen a un
registro de tu actividad y de tu red domestica.

## Privacidad y seguridad — leer antes de compartir o publicar este proyecto

- **Llamadas a un servicio externo**: cada IP publica nueva que
  aparece en "Conexiones activas" se envia a `ip-api.com` (gratuito,
  sin registro) para resolver su ubicacion. Es la IP del servidor
  remoto, no datos tuyos, pero es trafico hacia un tercero que debes
  conocer. Esa consulta viaja por HTTP simple (no HTTPS), ya que es el
  limite del nivel gratuito de ese servicio.
- **Escaneo activo de tu propia red**: la pestaña "Quien esta en mi
  red" envia trafico (ping/conexiones TCP cortas) a cada IP de tu
  subred para descubrir dispositivos. Es una accion legitima sobre tu
  propia red (igual que herramientas como Fing o Wireless Network
  Watcher), pero genera trafico real en tu LAN -- por eso es manual o
  cada 90s, nunca cada 2s.
- **No hay captura de paquetes ni inspeccion de contenido.** El
  sistema usa unicamente contadores y conexiones que expone el
  sistema operativo via `psutil`, mas un sondeo activo de la propia
  subred. No instala drivers, no usa Npcap/WinPcap, y no puede ver el
  contenido real de lo transmitido — mucho menos en conexiones
  cifradas (HTTPS), que son la mayoria del trafico moderno. El
  "volumen aprox. en MB" de la pestaña "Quien extrae tus datos" es una
  estimacion (reparte el trafico total de la tarjeta de red entre las
  conexiones activas en cada instante), no una medicion exacta por
  conexion.
- **Las unicas acciones irreversibles son**: cerrar procesos (a
  peticion explicita, con confirmacion) y crear/eliminar reglas de
  Firewall de Windows para una IP especifica (tambien a peticion
  explicita). Nada se ejecuta automaticamente sin que tu lo decidas en
  el momento.
- **Antes de subir este proyecto a un repositorio** (GitHub u otro):
  - No subas ningun `.csv` generado (`network_monitor_log.csv`,
    `egress_log.csv`, `attack_log.csv`, `known_devices.csv`) — ya
    estan en `.gitignore`, pero verifica que no hayan quedado
    rastreados si alguna vez los agregaste manualmente con `git add`.
  - El codigo en si no contiene rutas absolutas, usuario, correo,
    contraseñas ni claves de API — fue revisado para confirmarlo.
  - Si personalizas `requirements_agent.py` con rutas propias (por
    ejemplo, cambias `log_path` a una ruta absoluta de tu equipo),
    revisalo antes de publicar.

## Limitaciones conocidas

- Sin permisos de administrador, algunos procesos de otros usuarios no
  muestran su nombre (apareceran como "Desconocido") ni se pueden
  cerrar, y las reglas de Firewall no se pueden crear.
- El volumen de datos por conexion es una aproximacion, no un valor
  exacto.
- No se puede ver el contenido real de la informacion transmitida.
- La deteccion de ataques solo ve conexiones que llegan a crear una
  entrada en el sistema operativo; trafico bloqueado antes por el
  Firewall no es visible para esta app.
- El escaneo de "Quien esta en mi red" depende de que el dispositivo
  responda a ping/TCP o aparezca en la tabla ARP; dispositivos con
  firewall muy estricto o en modo ahorro de energia profundo pueden no
  aparecer.
- El fabricante/tipo de dispositivo es una suposicion (MAC + nombre de
  host), no una identificacion certera del sistema operativo.
- Las consultas de geolocalizacion y de nombre de host dependen de
  servicios externos / DNS y pueden tardar o fallar sin que eso
  afecte al resto del monitoreo.
