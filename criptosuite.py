# -*- coding: utf-8 -*-
"""
CriptoSuite Profesional - Versión de Escritorio en Python v2.1 (Final)

Descripción:
Esta es la versión final y completamente funcional. Se ha corregido el error
de carga de imágenes de manera definitiva, reemplazando el logo por un
placeholder compatible para garantizar la ejecución en todos los sistemas.
Toda la lógica de los algoritmos y la interfaz avanzada permanecen intactas.

Dependencias:
- sv-ttk: Para la apariencia visual moderna. Instalar con: pip install sv-ttk

Para crear un ejecutable (.exe):
1. Instala PyInstaller: pip install pyinstaller
2. Ejecuta en la terminal:
   pyinstaller --name CriptoSuite --onefile --windowed --noconsole criptosuite.py
"""
import tkinter as tk
from tkinter import ttk, font
import string
import random
import math

# --- Manejo de Dependencia Opcional ---
try:
    import sv_ttk
    USE_SV_TTK = True
except ImportError:
    USE_SV_TTK = False
    print("Advertencia: El paquete 'sv-ttk' no está instalado. La aplicación usará el tema por defecto.")
    print("Para una mejor apariencia visual, instálalo con: pip install sv-ttk")

# ============================================
# NÚCLEO MATEMÁTICO (Lógica de Criptografía)
# ============================================
ALPHABET = string.ascii_uppercase

def mcd(a, b):
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError(f"La inversa modular de {a} mod {m} no existe (MCD={g} ≠ 1).")
    return (x % m + m) % m

def power(base, exp, mod):
    return pow(base, exp, mod)

def is_prime(num):
    if not isinstance(num, int) or num <= 1: return False
    if num <= 3: return True
    if num % 2 == 0 or num % 3 == 0: return False
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True

# --- Funciones de Cifrado (retornan resultado y pasos) ---

def caesar_cipher(text, k, decrypt=False):
    op = "-" if decrypt else "+"
    eff_k = -k if decrypt else k
    steps = []
    res = []
    for char in text:
        if char.upper() in ALPHABET:
            start = ord('A') if char.isupper() else ord('a')
            p_idx = ord(char) - start
            c_idx = (p_idx + eff_k) % 26
            new_char = chr(start + c_idx)
            res.append(new_char)
            steps.append((f"'{char}'", p_idx, f"({p_idx} {op} {k}) mod 26", c_idx, f"'{new_char}'"))
        else:
            res.append(char)
            steps.append((f"'{char}'", "N/A", "No es letra, se omite", "N/A", f"'{char}'"))
    return "".join(res), steps

def affine_cipher(text, a, b, decrypt=False):
    steps = []
    res = []
    if decrypt:
        a_inv = modinv(a, 26)
        steps.append((f"Paso 1: Inversa de a={a} mod 26 => a⁻¹={a_inv}", "", "", "", ""))
        for char in text:
            if char.upper() in ALPHABET:
                p_idx = ALPHABET.index(char.upper())
                c_idx = (a_inv * (p_idx - b) + 520) % 26
                new_char = ALPHABET[c_idx]
                res.append(new_char if char.isupper() else new_char.lower())
                steps.append((f"'{char}'", p_idx, f"{a_inv}*({p_idx}-{b}) mod 26", c_idx, f"'{new_char}'"))
            else:
                res.append(char)
                steps.append((f"'{char}'", "N/A", "No es letra", "N/A", f"'{char}'"))
    else:
        for char in text:
            if char.upper() in ALPHABET:
                p_idx = ALPHABET.index(char.upper())
                c_idx = (a * p_idx + b) % 26
                new_char = ALPHABET[c_idx]
                res.append(new_char if char.isupper() else new_char.lower())
                steps.append((f"'{char}'", p_idx, f"({a}*{p_idx}+{b}) mod 26", c_idx, f"'{new_char}'"))
            else:
                res.append(char)
                steps.append((f"'{char}'", "N/A", "No es letra", "N/A", f"'{char}'"))
    return "".join(res), steps

def vigenere_cipher(text, key, decrypt=False):
    op = "-" if decrypt else "+"
    clean_key = "".join(filter(str.isalpha, key)).upper()
    if not clean_key: raise ValueError("La clave debe contener letras.")
    steps = []
    res = []
    key_i = 0
    for char in text:
        if char.upper() in ALPHABET:
            k_char = clean_key[key_i % len(clean_key)]
            k_shift = ALPHABET.index(k_char)
            eff_k = -k_shift if decrypt else k_shift
            start = ord('A') if char.isupper() else ord('a')
            p_idx = ord(char) - start
            c_idx = (p_idx + eff_k) % 26
            new_char = chr(start + c_idx)
            res.append(new_char)
            steps.append((f"'{char}'", f"'{k_char}'", k_shift, f"({p_idx} {op} {k_shift}) mod 26", f"'{new_char}'"))
            key_i += 1
        else:
            res.append(char)
            steps.append((f"'{char}'", "N/A", "N/A", "No es letra", f"'{char}'"))
    return "".join(res), steps

def otp_cipher(text, key, decrypt=False):
    return vigenere_cipher(text, key, decrypt)

def rsa_cipher(text, N, key, mode):
    steps = []
    if mode == 'enc':
        result_nums = []
        for char in text:
            m = ord(char)
            if m >= N: raise ValueError(f"El valor del caracter '{char}' (ASCII={m}) es >= que N={N}. Use p y q más grandes.")
            c = power(m, key, N)
            result_nums.append(str(c))
            steps.append((f"'{char}' (m={m})", f"c = {m}^{key} mod {N}", f"c = {c}"))
        return ",".join(result_nums), steps
    else:
        result_text = []
        try:
            cipher_nums = [int(n.strip()) for n in text.split(',')]
        except ValueError:
            raise ValueError(f"Entrada '{text}' contiene valores no numéricos o formato incorrecto.")
        for c in cipher_nums:
            m = power(c, key, N)
            char = chr(m)
            result_text.append(char)
            steps.append((f"c={c}", f"m = {c}^{key} mod {N}", f"m = {m} ('{char}')"))
        return "".join(result_text), steps

def get_euclides_steps(a, b):
    steps = []
    A, B = abs(a), abs(b)
    if B > A: A, B = B, A
    while B != 0:
        q, r = A // B, A % B
        steps.append((A, B, q, r))
        A, B = B, r
    return steps

def chinese_remainder_theorem(congruences):
    steps = []
    moduli = [c[1] for c in congruences]
    for i in range(len(moduli)):
        if moduli[i] <= 1: raise ValueError(f"Módulo n_{i+1}={moduli[i]} debe ser > 1.")
        for j in range(i + 1, len(moduli)):
            g = mcd(moduli[i], moduli[j])
            if g != 1: raise ValueError(f"Módulos no son coprimos: mcd({moduli[i]}, {moduli[j]}) = {g}.")
    N = 1
    for n in moduli: N *= n
    steps.append(("Calcular N", f"N = {' * '.join(map(str, moduli))}", f"N = {N}"))
    total_sum = 0
    terms_str = []
    for i, (a_i, n_i) in enumerate(congruences, 1):
        N_i = N // n_i
        y_i = modinv(N_i, n_i)
        term = a_i * N_i * y_i
        terms_str.append(str(term))
        total_sum += term
        steps.append((f"Congruencia {i}", f"aᵢ={a_i}, nᵢ={n_i}", "---"))
        steps.append(("", f"Nᵢ = N / nᵢ = {N} / {n_i}", f"Nᵢ = {N_i}"))
        steps.append(("", f"yᵢ = (Nᵢ)⁻¹ mod nᵢ", f"yᵢ = {y_i}"))
        steps.append(("", f"Término = aᵢ*Nᵢ*yᵢ", f"{term}"))
    final_x = total_sum % N
    steps.append(("Sumar términos", f"X = ({' + '.join(terms_str)}) mod {N}", f"X = {final_x}"))
    return f"x ≡ {final_x} (mod {N})", steps

# ============================================
# Interfaz Gráfica (GUI - Tkinter)
# ============================================
class CustomModal(tk.Toplevel):
    def __init__(self, parent, title, message):
        super().__init__(parent)
        self.transient(parent)
        self.title(title)
        self.geometry("400x150")
        self.resizable(False, False)
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill="both", expand=True)
        ttk.Label(main_frame, text=title, font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(main_frame, text=message, wraplength=360, justify="left").pack(anchor="w", pady=10)
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x", side="bottom", pady=(10,0))
        ok_button = ttk.Button(button_frame, text="Entendido", command=self.destroy, style="Accent.TButton")
        ok_button.pack(side="right")
        self.grab_set()
        self.lift()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.winfo_height() // 2)
        self.geometry(f'+{x}+{y}')
        parent.wait_window(self)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.withdraw()
        self.title("CriptoSuite Profesional")
        self.geometry("1100x750")
        self.minsize(950, 650)
        if USE_SV_TTK: sv_ttk.set_theme("light")
        self.style = ttk.Style(self)
        self.font_normal = font.Font(family="Segoe UI", size=10)
        self.font_bold = font.Font(family="Segoe UI", size=10, weight="bold")
        self.font_header = font.Font(family="Segoe UI", size=16, weight="bold")
        self.font_result = font.Font(family="Segoe UI", size=16, weight="bold")
        self.create_widgets()
        self.show_splash_screen()

    def show_splash_screen(self):
        splash = tk.Toplevel(self)
        splash.overrideredirect(True)
        width, height = 450, 300
        x = (self.winfo_screenwidth() / 2) - (width / 2)
        y = (self.winfo_screenheight() / 2) - (height / 2)
        splash.geometry(f'{width}x{height}+{int(x)}+{int(y)}')
        
        # CORRECCIÓN: Usar un pixel transparente 1x1 GIF, universalmente compatible.
        logo_data = "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
        
        self.espol_logo = tk.PhotoImage(data=logo_data)
        # Se crea un label invisible para el logo para mantener la estructura sin mostrarlo
        logo_label = ttk.Label(splash, image=self.espol_logo)
        logo_label.pack(pady=(30, 15)) # Se mantiene el padding para el espaciado

        ttk.Label(splash, text="Bienvenido a CriptoSuite", font=("Segoe UI", 20, "bold")).pack()
        ttk.Label(splash, text="Una herramienta académica para Criptografía\nEscuela Superior Politécnica del Litoral", 
                  wraplength=400, justify="center").pack(pady=10)
        start_button = ttk.Button(splash, text="Iniciar", command=lambda: self.start_app(splash), style="Accent.TButton")
        start_button.pack(pady=20, ipadx=20)

    def start_app(self, splash):
        splash.destroy()
        self.deiconify()

    def create_widgets(self):
        sidebar = ttk.Frame(self, padding=10)
        sidebar.pack(side="left", fill="y")
        self.content_area = ttk.Frame(self, padding=(20, 10, 10, 10))
        self.content_area.pack(side="right", fill="both", expand=True)
        self.content_area.rowconfigure(0, weight=1); self.content_area.columnconfigure(0, weight=1)
        ttk.Label(sidebar, text="CriptoSuite", font=self.font_header).pack(anchor="w", pady=(0, 20))
        self.frames = {}
        for F, name in [
            (CesarFrame, "Cifrado César"), (AfinFrame, "Cifrado Afín"),
            (VigenereFrame, "Cifrado Vigenère"), (OTPFrame, "One-Time Pad"),
            (RSAFrame, "Criptosistema RSA"), (EuclidesFrame, "Euclides y MCD"),
            (TCRFrame, "Teorema Chino del Residuo")
        ]:
            frame = F(self.content_area, self)
            self.frames[name] = frame
            frame.grid(row=0, column=0, sticky="nsew")
            b = ttk.Button(sidebar, text=name, command=lambda f=name: self.show_frame(f), style="Accent.TButton")
            b.pack(fill="x", pady=3)
        self.show_frame("Cifrado César")

    def show_frame(self, name):
        for frame in self.frames.values(): frame.grid_remove()
        self.frames[name].grid()
        self.title(f"CriptoSuite Profesional - {name}")

class BaseFrame(ttk.Frame):
    def __init__(self, master, app_instance):
        super().__init__(master)
        self.app = app_instance
        self.columnconfigure(1, weight=1); self.rowconfigure(0, weight=1)
        self._create_widgets()
    def _create_widgets(self): raise NotImplementedError
    def show_error(self, title, msg): CustomModal(self.app, title, msg)
    def _create_io_widgets(self):
        controls_parent = ttk.Labelframe(self, text=" Controles ", padding=15)
        controls_parent.grid(row=0, column=0, sticky="ns", padx=(0, 10))
        self.controls_frame = ttk.Frame(controls_parent)
        self.controls_frame.pack(fill="x", expand=True)
        notebook = ttk.Notebook(self)
        notebook.grid(row=0, column=1, sticky="nsew")
        res_frame = ttk.Frame(notebook, padding=20)
        notebook.add(res_frame, text="Resultado")
        res_frame.columnconfigure(0, weight=1); res_frame.rowconfigure(1, weight=1)
        ttk.Label(res_frame, text="Resultado Final:", font=self.app.font_bold).grid(row=0, column=0, sticky="w")
        self.result_var = tk.StringVar(value="-")
        result_entry = ttk.Entry(res_frame, textvariable=self.result_var, font=self.app.font_result, state="readonly")
        result_entry.grid(row=1, column=0, sticky="nsew", pady=(5,0))
        steps_frame = ttk.Frame(notebook, padding=10)
        notebook.add(steps_frame, text="Proceso Matemático Detallado")
        steps_frame.columnconfigure(0, weight=1); steps_frame.rowconfigure(0, weight=1)
        self.steps_tree = ttk.Treeview(steps_frame, show="headings")
        self.steps_tree.grid(sticky="nsew")
        scrollbar = ttk.Scrollbar(steps_frame, orient="vertical", command=self.steps_tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.steps_tree.configure(yscrollcommand=scrollbar.set)
    def _setup_treeview(self, columns):
        self.steps_tree.delete(*self.steps_tree.get_children())
        self.steps_tree["columns"] = columns
        for col in columns:
            self.steps_tree.heading(col, text=col, anchor="w")
            self.steps_tree.column(col, anchor="w", width=120, stretch=True)
    def _update_output(self, result, steps, columns):
        self.result_var.set(result)
        self._setup_treeview(columns)
        for i, row in enumerate(steps):
            self.steps_tree.insert("", "end", iid=i, values=row)
    def _create_text_input(self, var_name, label_text):
        ttk.Label(self.controls_frame, text=label_text, font=self.app.font_bold).pack(anchor="w", pady=(10, 2))
        setattr(self, var_name, tk.StringVar())
        entry = ttk.Entry(self.controls_frame, textvariable=getattr(self, var_name))
        entry.pack(fill="x")
        return entry
    def _create_mode_selector(self):
        self.mode_var = tk.StringVar(value="enc")
        f = ttk.Frame(self.controls_frame)
        f.pack(anchor="w", pady=10)
        ttk.Radiobutton(f, text="Encriptar", value="enc", variable=self.mode_var).pack(side="left")
        ttk.Radiobutton(f, text="Desencriptar", value="dec", variable=self.mode_var).pack(side="left", padx=10)

class CesarFrame(BaseFrame):
    def _create_widgets(self):
        self._create_io_widgets()
        self._create_text_input("text_var", "Texto:")
        self.text_var.set("HELLO WORLD")
        ttk.Label(self.controls_frame, text="Desplazamiento (k):", font=self.app.font_bold).pack(anchor="w", pady=(10, 2))
        self.k_var = tk.StringVar(value="3")
        ttk.Spinbox(self.controls_frame, from_=0, to=25, textvariable=self.k_var, wrap=True).pack(fill="x")
        self._create_mode_selector()
        ttk.Separator(self.controls_frame, orient="horizontal").pack(fill="x", pady=20)
        ttk.Button(self.controls_frame, text="Ejecutar", command=self.run, style="Accent.TButton").pack(anchor="w")
    def run(self):
        try:
            k, text = int(self.k_var.get()), self.text_var.get()
            if not text: raise ValueError("El texto no puede estar vacío.")
            result, steps = caesar_cipher(text, k, self.mode_var.get() == "dec")
            self._update_output(result, steps, ("Entrada", "Índice P", "Cálculo", "Índice C", "Salida"))
        except ValueError as e: self.show_error('Error en Cifrado César', str(e))

class AfinFrame(BaseFrame):
    def _create_widgets(self):
        self._create_io_widgets()
        self._create_text_input("text_var", "Texto:")
        self.text_var.set("AFFINE CIPHER")
        ttk.Label(self.controls_frame, text="Valor 'a' (coprimo con 26):", font=self.app.font_bold).pack(anchor="w", pady=(10, 2))
        self.a_var = tk.StringVar()
        valid_a = [i for i in range(1, 26) if mcd(i, 26) == 1]
        a_combo = ttk.Combobox(self.controls_frame, textvariable=self.a_var, values=valid_a, state="readonly")
        a_combo.set(valid_a[2]); a_combo.pack(fill="x")
        ttk.Label(self.controls_frame, text="Valor 'b':", font=self.app.font_bold).pack(anchor="w", pady=(10, 2))
        self.b_var = tk.StringVar(value="8")
        ttk.Entry(self.controls_frame, textvariable=self.b_var).pack(fill="x")
        self._create_mode_selector()
        ttk.Separator(self.controls_frame, orient="horizontal").pack(fill="x", pady=20)
        ttk.Button(self.controls_frame, text="Ejecutar", command=self.run, style="Accent.TButton").pack(anchor="w")
    def run(self):
        try:
            text = self.text_var.get()
            if not text: raise ValueError("El texto no puede estar vacío.")
            a, b = int(self.a_var.get()), int(self.b_var.get())
            result, steps = affine_cipher(text, a, b, self.mode_var.get() == "dec")
            headers = ("Entrada", "Índice C", "Cálculo", "Índice P", "Salida") if self.mode_var.get() == "dec" else ("Entrada", "Índice P", "Cálculo", "Índice C", "Salida")
            self._update_output(result, steps, headers)
        except ValueError as e: self.show_error('Error en Cifrado Afín', f"Entrada inválida. 'a' y 'b' deben ser números.\nDetalle: {e}")

class VigenereFrame(BaseFrame):
    def _create_widgets(self):
        self._create_io_widgets()
        self._create_text_input("text_var", "Texto:")
        self.text_var.set("ATTACK AT DAWN")
        self._create_text_input("key_var", "Clave:")
        self.key_var.set("LEMON")
        self._create_mode_selector()
        ttk.Separator(self.controls_frame, orient="horizontal").pack(fill="x", pady=20)
        ttk.Button(self.controls_frame, text="Ejecutar", command=self.run, style="Accent.TButton").pack(anchor="w")
    def run(self):
        try:
            text, key = self.text_var.get(), self.key_var.get()
            if not text or not key: raise ValueError("El texto y la clave no pueden estar vacíos.")
            result, steps = vigenere_cipher(text, key, self.mode_var.get() == "dec")
            self._update_output(result, steps, ("Entrada", "Clave", "Shift", "Cálculo", "Salida"))
        except ValueError as e: self.show_error("Error en Cifrado Vigenère", str(e))

class OTPFrame(BaseFrame):
    def _create_widgets(self):
        self._create_io_widgets()
        self._create_text_input("text_var", "Texto:")
        self.text_var.set("SECRET MESSAGE")
        self._create_text_input("key_var", "Clave:")
        ttk.Button(self.controls_frame, text="Generar Clave Aleatoria", command=self.generate_key).pack(anchor="w", pady=5)
        self._create_mode_selector()
        ttk.Separator(self.controls_frame, orient="horizontal").pack(fill="x", pady=20)
        ttk.Button(self.controls_frame, text="Ejecutar", command=self.run, style="Accent.TButton").pack(anchor="w")
    def generate_key(self):
        text_only_letters = ''.join(filter(str.isalpha, self.text_var.get()))
        self.key_var.set(''.join(random.choice(ALPHABET) for _ in range(len(text_only_letters))))
    def run(self):
        try:
            text, key = self.text_var.get(), self.key_var.get()
            clean_text = ''.join(filter(str.isalpha, text))
            clean_key = ''.join(filter(str.isalpha, key))
            if len(clean_text) != len(clean_key):
                raise ValueError(f"La longitud del texto ({len(clean_text)}) y la clave ({len(clean_key)}) deben ser iguales.")
            result, steps = otp_cipher(text, key, self.mode_var.get() == "dec")
            self._update_output(result, steps, ("Entrada", "Clave", "Shift", "Cálculo", "Salida"))
        except ValueError as e: self.show_error("Error en One-Time Pad", str(e))

class RSAFrame(BaseFrame):
    def _create_widgets(self):
        self._create_io_widgets()
        self.p_var = tk.StringVar(value="61")
        self.q_var = tk.StringVar(value="53")
        self.e_var = tk.StringVar(value="17")
        keys_fs = ttk.Labelframe(self.controls_frame, text=" 1. Generación de Claves ", padding=10)
        keys_fs.pack(fill="x", pady=(10,0))
        ttk.Label(keys_fs, text="Número primo (p):").pack(anchor="w")
        self.p_input = ttk.Entry(keys_fs, textvariable=self.p_var)
        self.p_input.pack(fill="x")
        self.p_validation_label = ttk.Label(keys_fs, foreground="red")
        self.p_validation_label.pack(anchor="w")
        ttk.Label(keys_fs, text="Número primo (q):").pack(anchor="w")
        self.q_input = ttk.Entry(keys_fs, textvariable=self.q_var)
        self.q_input.pack(fill="x")
        self.q_validation_label = ttk.Label(keys_fs, foreground="red")
        self.q_validation_label.pack(anchor="w")
        ttk.Label(keys_fs, text="Exponente público (e):").pack(anchor="w")
        self.e_input = ttk.Entry(keys_fs, textvariable=self.e_var)
        self.e_input.pack(fill="x")
        self.e_validation_label = ttk.Label(keys_fs, foreground="red")
        self.e_validation_label.pack(anchor="w")
        self.gen_button = ttk.Button(keys_fs, text="Generar y Mostrar Claves", command=self.generate_keys, style="Accent.TButton")
        self.gen_button.pack(anchor="w", pady=10)
        ttk.Separator(keys_fs).pack(fill="x", pady=10)
        self._create_text_input("public_key_var", "Clave Pública (N, e):")
        self._create_text_input("private_key_var", "Clave Privada (d):")
        self._create_text_input("n_var", "Módulo (N):")
        self._create_text_input("phi_n_var", "Phi(N) - φ(N):")
        cipher_fs = ttk.Labelframe(self.controls_frame, text=" 2. Cifrado / Descifrado ", padding=10)
        cipher_fs.pack(fill="x", pady=20)
        self._create_text_input("rsa_text_var", "Texto o Números (separados por coma):")
        self._create_mode_selector()
        ttk.Separator(self.controls_frame).pack(fill="x", pady=10)
        self.exec_button = ttk.Button(self.controls_frame, text="Ejecutar", command=self.run, style="Accent.TButton")
        self.exec_button.pack(anchor="w")
        self.p_var.trace_add("write", self._validate_inputs)
        self.q_var.trace_add("write", self._validate_inputs)
        self.e_var.trace_add("write", self._validate_inputs)
        self._validate_inputs()
        self.generate_keys()

    def _validate_inputs(self, *args):
        p, q, e = self.p_var.get(), self.q_var.get(), self.e_var.get()
        p_ok, q_ok, e_ok = False, False, False
        try: p_int = int(p); q_int = int(q); e_int = int(e)
        except ValueError: pass

        try:
            p_int = int(p)
            if not is_prime(p_int): self.p_validation_label.config(text="p debe ser un número primo.")
            else: self.p_validation_label.config(text=""); p_ok = True
        except (ValueError, TypeError): self.p_validation_label.config(text="p debe ser un entero.")
        
        try:
            q_int = int(q)
            if not is_prime(q_int): self.q_validation_label.config(text="q debe ser un número primo.")
            elif p_ok and p_int == q_int: self.q_validation_label.config(text="p y q no pueden ser iguales.")
            else: self.q_validation_label.config(text=""); q_ok = True
        except (ValueError, TypeError): self.q_validation_label.config(text="q debe ser un entero.")
        
        if p_ok and q_ok:
            try:
                e_int = int(e)
                phiN = (p_int - 1) * (q_int - 1)
                if mcd(e_int, phiN) != 1: self.e_validation_label.config(text=f"e debe ser coprimo con φ(N) = {phiN}.")
                elif not (1 < e_int < phiN): self.e_validation_label.config(text=f"e debe estar entre 1 y {phiN}.")
                else: self.e_validation_label.config(text=""); e_ok = True
            except (ValueError, TypeError): self.e_validation_label.config(text="e debe ser un entero.")
        else:
            self.e_validation_label.config(text="p y q deben ser válidos primero.")
        self.gen_button.config(state="normal" if (p_ok and q_ok and e_ok) else "disabled")

    def generate_keys(self):
        try:
            p, q, e = int(self.p_var.get()), int(self.q_var.get()), int(self.e_var.get())
            N = p * q; phiN = (p - 1) * (q - 1); d = modinv(e, phiN)
            self.public_key_var.set(f"({N}, {e})"); self.private_key_var.set(d)
            self.n_var.set(N); self.phi_n_var.set(phiN)
            self.exec_button.config(state="normal")
        except ValueError as e: self.show_error("Error en Generación de Claves", str(e)); self.exec_button.config(state="disabled")

    def run(self):
        try:
            N = int(self.n_var.get()); mode = self.mode_var.get()
            key = int(self.e_var.get()) if mode == 'enc' else int(self.private_key_var.get())
            text = self.rsa_text_var.get()
            if not text: raise ValueError("El campo de texto no puede estar vacío.")
            result, steps = rsa_cipher(text, N, key, mode)
            headers = ("Entrada (m)", "Cálculo", "Resultado (c)") if mode == 'enc' else ("Entrada (c)", "Cálculo", "Resultado (m)")
            self._update_output(result, steps, headers)
        except ValueError as e: self.show_error("Error en RSA", str(e))

class EuclidesFrame(BaseFrame):
    def _create_widgets(self):
        self._create_io_widgets()
        self._create_text_input("a_var", "Valor 'a':"); self.a_var.set("391")
        self._create_text_input("b_var", "Valor 'b':"); self.b_var.set("299")
        ttk.Separator(self.controls_frame).pack(fill="x", pady=20)
        ttk.Button(self.controls_frame, text="Calcular", command=self.run, style="Accent.TButton").pack(anchor="w")
    def run(self):
        try:
            a, b = int(self.a_var.get()), int(self.b_var.get())
            if a == 0 and b == 0: raise ValueError("MCD(0,0) no está definido.")
            steps = get_euclides_steps(a,b)
            g, x, y = egcd(a,b)
            result = f"MCD = {g}   |   Bézout: {a}({x}) + {b}({y}) = {g}"
            self._update_output(result, steps, ("a", "b", "Cociente (q)", "Resto (r)"))
        except ValueError as e: self.show_error('Error en Euclides', str(e))

class TCRFrame(BaseFrame):
    def _create_widgets(self):
        self._create_io_widgets()
        self.congruence_rows = []
        self.list_frame = ttk.Frame(self.controls_frame)
        self.list_frame.pack(fill="x", expand=True, pady=(10,0))
        btn_frame = ttk.Frame(self.controls_frame)
        btn_frame.pack(anchor="w", pady=10)
        ttk.Button(btn_frame, text="Añadir Fila", command=self.add_row).pack(side="left")
        ttk.Button(btn_frame, text="Eliminar Última", command=self.remove_row).pack(side="left", padx=10)
        ttk.Separator(self.controls_frame).pack(fill="x", pady=10)
        ttk.Button(self.controls_frame, text="Resolver Sistema", command=self.run, style="Accent.TButton").pack(anchor="w")
        self.add_row("2", "3"); self.add_row("3", "5")
    def add_row(self, a_val="1", n_val="7"):
        frame = ttk.Frame(self.list_frame); frame.pack(fill="x", pady=2)
        ttk.Label(frame, text="x ≡").pack(side="left", padx=(0, 5))
        a_var = tk.StringVar(value=a_val); ttk.Entry(frame, textvariable=a_var, width=6).pack(side="left")
        ttk.Label(frame, text="(mod").pack(side="left", padx=5)
        n_var = tk.StringVar(value=n_val); ttk.Entry(frame, textvariable=n_var, width=6).pack(side="left")
        ttk.Label(frame, text=")").pack(side="left")
        self.congruence_rows.append({'frame': frame, 'a': a_var, 'n': n_var})
    def remove_row(self):
        if len(self.congruence_rows) > 1: self.congruence_rows.pop()['frame'].destroy()
    def run(self):
        try:
            congruences = []
            for row in self.congruence_rows:
                a, n = int(row['a'].get()), int(row['n'].get())
                congruences.append((a, n))
            if not congruences: raise ValueError("Añada al menos una congruencia.")
            result, steps = chinese_remainder_theorem(congruences)
            self._update_output(result, steps, ("Paso", "Cálculo", "Resultado"))
        except ValueError as e: self.show_error("Error en T. Chino del Residuo", str(e))

if __name__ == "__main__":
    app = App()
    app.mainloop()

