# 🍸 RiCharEpoint – SharePoint 2025 RCE Exploitation GUI
<img width="3349" height="1280" alt="logo" src="https://github.com/user-attachments/assets/8a9b9c18-4594-402c-8872-dac9470e383a" />  

  
Bienvenido a **RiCharEpoint**, una herramienta desarrollada por *Un Hacker En Capital* para **validar y explotar de forma controlada** la reciente vulnerabilidad de **Remote Code Execution (RCE)** en **Microsoft SharePoint**, descubierta en 2025.

> 🔐 Esta vulnerabilidad está clasificada como **Alta criticidad**, ya que permite la **ejecución remota de código sin autenticación** en entornos SharePoint expuestos.

Los identificadores CVE asociados son:

- **CVE-2025-53770**
- **CVE-2025-53771**
- **CVE-2025-49704**
- **CVE-2025-49706**

---

## 🔍 ¿Qué hace RiCharEpoint?

RiCharEpoint permite:

* 🎯 **Validar** si un servidor SharePoint es vulnerable a las nuevas RCEs de 2025.
* 💻 **Explotar** automáticamente la vulnerabilidad usando **Metasploit Framework** para obtener una shell reversa (*Meterpreter*).
* 🖥️ **Gestionar todo desde un GUI intuitivo**, sin necesidad de ejecutar comandos manuales en Metasploit.
* 🔄 **Reutilizar el GUI** como *launcher* para otros módulos `.rb` de Metasploit.

---

## ⚙️ ¿Cómo funciona?

La herramienta actúa como interfaz de control para **Metasploit Framework**, simplificando la ejecución de los exploits:

1. Se carga un **script `.rb`** correspondiente a la vulnerabilidad.
2. Se configuran los parámetros de conexión (IP/Host, Puerto, VHOST, LHOST, LPORT).
3. Se arranca **msfconsole** en una sesión interna y se inyecta el módulo.
4. Se setean las variables y se ejecutan las fases **check** y **run**.

Esto permite que tanto la validación como la explotación se realicen de forma centralizada desde la interfaz gráfica.

---

## 🧑‍💻 Interfaz

La aplicación está escrita en **Python + PyQt5** e incluye:

* 📂 Selección de archivo `.rb` del exploit.
* 🌐 Configuración de **RHOSTS**, **RPORT**, **VHOST**, **LHOST** y **LPORT**.
* 🔘 Botones para:
  - **Iniciar msfconsole**
  - **Inyectar módulo**
  - **Setear variables**
  - **Check** (validar vulnerabilidad)
  - **Run** (explotar)
* 📜 Área de logs para ver en tiempo real la ejecución.

---

## 📸 Guía paso a paso

### 1️⃣ Pantalla principal  

<img width="1000" height="630" alt="Captura de pantalla 2025-08-08 142302" src="https://github.com/user-attachments/assets/a583eef6-b67f-4211-b2ad-f5a101453e39" />

Ejecutar Script:

```bash
Python3 RiCharEpoint.py
```

Carga de valores **IP/Host**, puerto donde corre SharePoint, Virtual Host y selección de **LAN** o **Remoto**.  
Verifica que la IP detectada sea correcta.

---

### 2️⃣ Cargar script `.rb`  

<img width="338" height="119" alt="Captura de pantalla 2025-08-08 142317" src="https://github.com/user-attachments/assets/e0ab8373-eb55-4215-a8f0-1f3b98995997" />

Presionar **Seleccionar .rb** y elegir el exploit correspondiente, disponible en el repositorio oficial de Metasploit: 
🔗[https://github.com/UnHackerEnCapital/RiCharEpoint/blob/main/RiCharEpoint.rb](https://github.com/UnHackerEnCapital/RiCharEpoint/blob/main/RiCharEpoint.rb)
 
Creditos : https://github.com/rapid7/metasploit-framework/pull/20409

Este script fue desarrollado por un grupo de profesionales y adaptado para uso en este GUI.

---

### 3️⃣ Iniciar Metasploit e inyectar el módulo  

<img width="1240" height="808" alt="Captura de pantalla 2025-08-08 142453" src="https://github.com/user-attachments/assets/f40f7354-aca3-49cf-8137-ec59e78388b7" />

Presionar **Iniciar msfconsole** para arrancar Metasploit Framework, y luego **Inyectar módulo** para cargar el exploit `.rb` correspondiente a la vulnerabilidad.

---

### 4️⃣ Setear variables  

<img width="998" height="622" alt="Captura de pantalla 2025-08-08 142516" src="https://github.com/user-attachments/assets/e046b30e-c25b-4584-b104-f2f8f0faf25e" />

Presionar **Setear variables** para que todos los valores configurados en el GUI se apliquen en el módulo activo.

---

### 5️⃣ Validar vulnerabilidad (**Check**)  

<img width="1247" height="372" alt="Captura de pantalla 2025-08-08 142556" src="https://github.com/user-attachments/assets/bf2eb7af-6cba-4feb-a6d4-3c52e3ed47ad" />

Presionar **Check** para ejecutar la validación.  
Si el objetivo es vulnerable, se mostrará un mensaje de confirmación en el log.

---

### 6️⃣ Explotar (**Run**)  

<img width="1260" height="375" alt="Captura de pantalla 2025-08-08 142614" src="https://github.com/user-attachments/assets/307a8de2-8496-4fff-8676-da8c3f5a0313" />

Una vez confirmado que el objetivo es vulnerable, presionar **Run** para ejecutar el exploit y obtener una **shell reversa Meterpreter**.  
Esto permite acceso remoto para ejecutar comandos en el servidor comprometido.

---

## 🚀 Uso

1. Configurar los datos de conexión.
2. Seleccionar el script `.rb`.
3. Iniciar msfconsole.
4. Inyectar módulo.
5. Setear variables.
6. Validar con **Check**.
7. Explotar con **Run**.

---
## 📆 Dependencias

Instalar con pip:

```bash
pip install PyQt5 requests
```

Dependencias necesarias:

- **PyQt5** – Interfaz gráfica.  
- **requests** – Detección de IP WAN.  

---

## 🧠 Autor

**Un Hacker En Capital**  
🎥 [YouTube](https://www.youtube.com/@unhackerencapital)  
🎮 [Twitch](https://twitch.tv/unhackerencapital)  
📱 [TikTok](https://www.tiktok.com/@unhackerencapital)  

---

## ⚠️ Disclaimer

> Esta herramienta se proporciona exclusivamente con fines educativos y de investigación para validar la seguridad de **servidores SharePoint propios** frente a las vulnerabilidades **CVE-2025-53770**, **CVE-2025-53771**, **CVE-2025-49704** y **CVE-2025-49706**.  
> No se responsabiliza al autor por usos indebidos fuera de entornos controlados.


