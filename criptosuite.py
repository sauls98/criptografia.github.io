import tkinter as tk
from tkinter import ttk, font, messagebox
import math
import random

# =================================================================================================
# SECCIÓN 1: LÓGICA CRIPTOGRÁFICA
# Contiene toda la matemática pura, portada directamente de la lógica de JavaScript.
# =================================================================================================
class CriptoMath:
    ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

    @staticmethod
    def mcd(a, b):
        return math.gcd(a, b)

    @staticmethod
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        g, y, x = CriptoMath.egcd(b % a, a)
        return (g, x - (b // a) * y, y)

    @staticmethod
    def modinv(a, m):
        if m <= 1:
            raise ValueError("El módulo debe ser mayor que 1.")
        g, x, y = CriptoMath.egcd(a, m)
        if g != 1:
            raise ValueError(f"La inversa de {a} mod {m} no existe (MCD={g} ≠ 1).")
        return (x % m + m) % m

    @staticmethod
    def power(base, exp, mod):
        return pow(base, exp, mod)

    @staticmethod
    def is_prime(num):
        if num < 2: return False
        if num == 2 or num == 3: return True
        if num % 2 == 0 or num % 3 == 0: return False
        i = 5
        while i * i <= num:
            if num % i == 0 or num % (i + 2) == 0:
                return False
            i += 6
        return True

    @staticmethod
    def caesar_cipher(text, b, decrypt=False):
        op = -1 if decrypt else 1
        effective_k = op * b
        result = ''
        steps = []
        for char in text:
            if char.upper() in CriptoMath.ALPHABET:
                char_code = ord(char)
                base = 65 if char.isupper() else 97
                P = char_code - base
                C = (P + effective_k) % 26
                new_char = chr(base + C)
                result += new_char
                steps.append((f"'{char}' (P={P})", f"({P} {'-' if decrypt else '+'} {b}) mod 26", f"'{new_char}' (C={C})"))
            else:
                result += char
                steps.append((f"'{char}'", 'No es una letra', f"'{char}'"))
        return {'result': result, 'steps': steps}

    @staticmethod
    def affine_cipher(text, a, b, decrypt=False):
        result, steps = '', []
        if decrypt:
            a_inv = CriptoMath.modinv(a, 26)
            steps.append(("Paso 1: Inversa", f"Inversa de a={a} mod 26", f"a⁻¹ = {a_inv}"))
            for char in text:
                if char.upper() in CriptoMath.ALPHABET:
                    C = CriptoMath.ALPHABET.find(char.upper())
                    P = (a_inv * (C - b)) % 26
                    new_char = CriptoMath.ALPHABET[P]
                    result += new_char.lower() if char.islower() else new_char
                    steps.append((f"'{char}' (C={C})", f"{a_inv}*({C}-{b}) mod 26", f"'{new_char}' (P={P})"))
                else:
                    result += char
                    steps.append((f"'{char}'", 'No es una letra', f"'{char}'"))
        else:
            for char in text:
                if char.upper() in CriptoMath.ALPHABET:
                    P = CriptoMath.ALPHABET.find(char.upper())
                    C = (a * P + b) % 26
                    new_char = CriptoMath.ALPHABET[C]
                    result += new_char.lower() if char.islower() else new_char
                    steps.append((f"'{char}' (P={P})", f"({a}*{P}+{b}) mod 26", f"'{new_char}' (C={C})"))
                else:
                    result += char
                    steps.append((f"'{char}'", 'No es una letra', f"'{char}'"))
        return {'result': result, 'steps': steps}

    @staticmethod
    def vigenere_cipher(text, key, decrypt=False):
        clean_key = ''.join(filter(str.isalpha, key)).upper()
        if not clean_key: raise ValueError("La llave debe contener al menos una letra.")
        result, steps, key_index = '', [], 0
        for char in text:
            if char.isalpha():
                k_char = clean_key[key_index % len(clean_key)]
                k_shift = CriptoMath.ALPHABET.find(k_char)
                sub_res = CriptoMath.caesar_cipher(char, k_shift, decrypt)
                result += sub_res['result']
                steps.append((f"'{char}'", f"'{k_char}'", k_shift, sub_res['steps'][0][1], sub_res['steps'][0][2]))
                key_index += 1
            else:
                result += char
                steps.append((f"'{char}'", 'N/A', 'N/A', 'No es una letra', f"'{char}'"))
        return {'result': result, 'steps': steps}
        
    @staticmethod
    def one_time_pad_cipher(text, key, decrypt=False):
        clean_key = ''.join(filter(str.isalpha, key)).upper()
        clean_text = ''.join(filter(str.isalpha, text))
        if len(clean_key) != len(clean_text):
            raise ValueError(f"La longitud del mensaje ({len(clean_text)}) y la llave ({len(clean_key)}) deben ser iguales.")
        # OTP es un caso especial de Vigenère
        return CriptoMath.vigenere_cipher(text, key, decrypt)

    @staticmethod
    def rsa_cipher(text, N, key, mode):
        steps = []
        if mode == 'enc':
            result = []
            for char in text:
                m = ord(char)
                if m >= N: raise ValueError(f"El valor ASCII de '{char}' ({m}) es >= N ({N}). Use primos p,q más grandes.")
                c = CriptoMath.power(m, key, N)
                result.append(str(c))
                steps.append((f"'{char}' (m={m})", f"c = {m}^{key} mod {N}", f"c = {c}"))
            return {'result': ",".join(result), 'steps': steps}
        else: # dec
            result = ''
            try:
                cipher_nums = [int(n.strip()) for n in text.split(',') if n.strip()]
            except (ValueError, TypeError):
                raise ValueError("El texto cifrado debe ser una lista de números separados por comas.")
            
            for c in cipher_nums:
                m = CriptoMath.power(c, key, N)
                char = chr(m)
                result += char
                steps.append((f"c={c}", f"m = {c}^{key} mod {N}", f"m = {m} ('{char}')"))
            return {'result': result, 'steps': steps}
            
    @staticmethod
    def euclides_algorithm(initial_a, initial_b):
        steps = []
        fa, fb = initial_a, initial_b
        if fa == 0 and fb == 0:
            raise ValueError("mcd(0, 0) no está definido.")
        a, b = abs(initial_a), abs(initial_b)
        prevx, x = 1, 0
        prevy, y = 0, 1

        while b:
            q = a // b
            r = a % b
            division_step = f"{a} = {b} * {q} + {r}"
            
            temp_x = x
            x = prevx - q * x
            prevx = temp_x

            temp_y = y
            y = prevy - q * y
            prevy = temp_y
            
            bezout_step = f"{r} = {fa}({x}) + {fb}({y})" if r else '---'
            steps.append((division_step, bezout_step))
            a, b = b, r

        g = a
        x_final, y_final = prevx, prevy
        result = f"mcd({fa}, {fb}) = {g}\nIdentidad de Bézout: {fa}({x_final}) + {fb}({y_final}) = {g}"
        return {'result': result, 'steps': steps}

    @staticmethod
    def chinese_remainder_theorem(congruences):
        steps = []
        if len(congruences) < 2:
            raise ValueError("Se necesitan al menos dos congruencias.")

        moduli = [n for r, n in congruences]
        for i in range(len(moduli)):
            if moduli[i] <= 1:
                raise ValueError(f"El módulo n_{i+1}={moduli[i]} debe ser > 1.")
            for j in range(i + 1, len(moduli)):
                if CriptoMath.mcd(moduli[i], moduli[j]) != 1:
                    raise ValueError(f"Módulos no coprimos: mcd({moduli[i]}, {moduli[j]}) = {CriptoMath.mcd(moduli[i], moduli[j])} ≠ 1.")
        
        r1, n1 = congruences[0]
        for i in range(1, len(congruences)):
            r2, n2 = congruences[i]
            steps.append((f"Resolviendo sistema parcial:", "", ""))
            steps.append((f"n ≡ {r1} (mod {n1})", "", ""))
            steps.append((f"n ≡ {r2} (mod {n2})", "", ""))

            g, x, y = CriptoMath.egcd(n1, n2)
            steps.append(("Usar Euclides Extendido", f"1 = {n1}({x}) + {n2}({y})", f"x={x}, y={y}"))

            n12 = r1 * y * n2 + r2 * x * n1
            steps.append(("Calcular n_1,2", f"r₁*y*n₂ + r₂*x*n₁", f"= {n12}"))

            new_mod = n1 * n2
            # CORRECCIÓN: Asegurar que el resultado del módulo sea positivo
            r1 = (n12 % new_mod + new_mod) % new_mod
            n1 = new_mod
            steps.append(("Nueva congruencia", f"n ≡ {n12} (mod {new_mod})", f"n ≡ {r1} (mod {n1})"))

        N = math.prod(moduli)
        result_str = f"n ≡ {r1} (mod {N})"
        return {'result': result_str, 'steps': steps}

# =================================================================================================
# SECCIÓN 2: APLICACIÓN PRINCIPAL (GUI con TKINTER)
# =================================================================================================
class CriptoSuiteApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CriptoSuite Profesional (Python Edition)")
        self.geometry("1200x750")
        self.minsize(1000, 600)

        # --- Estilo y Fuentes ---
        self.style = ttk.Style(self)
        try:
            # Intenta usar un tema moderno si está disponible
            from sv_ttk import set_theme
            set_theme("light")
        except ImportError:
            self.style.theme_use('clam')

        self.font_normal = font.nametofont("TkDefaultFont")
        self.font_bold = self.font_normal.copy(); self.font_bold.configure(weight="bold")
        self.font_title = self.font_normal.copy(); self.font_title.configure(size=16, weight="bold")
        self.font_result = font.Font(family="Consolas", size=14, weight="bold")
        self.font_small = self.font_normal.copy(); self.font_small.configure(size=9)
        
        self.configure(bg="#f3f4f6")
        self.style.configure("TFrame", background="#f3f4f6")
        self.style.configure("Card.TFrame", background="white", relief="solid", borderwidth=1, bordercolor="#d1d5db")
        self.style.configure("TLabel", background="#f3f4f6")
        self.style.configure("Card.TLabel", background="white")
        self.style.configure("Header.TLabel", font=self.font_title, foreground="#007aff", background="white")
        self.style.configure("Result.TLabel", font=self.font_result, background="#f3f4f6")
        self.style.configure("Success.TLabel", foreground="#10b981", background="white")
        self.style.configure("Error.TLabel", foreground="#ef4444", background="white")
        self.style.configure("Treeview", rowheight=28, fieldbackground="white")
        self.style.configure("Treeview.Heading", font=self.font_bold)
        self.style.configure("TNotebook", borderwidth=0)
        self.style.layout("TNotebook.Tab", []) # Ocultar tabs

        self._create_layout()

    def _create_layout(self):
        # Layout principal (Sidebar + Contenido)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # --- Sidebar de Navegación ---
        sidebar = ttk.Frame(self, width=250, style="Card.TFrame")
        sidebar.grid(row=0, column=0, sticky="ns", padx=(10,0), pady=10)
        sidebar.grid_propagate(False)
        
        ttk.Label(sidebar, text="CriptoSuite", style="Header.TLabel").pack(pady=20, padx=20, anchor='w')

        self.nav_buttons = {}
        self.notebook = ttk.Notebook(self, style="TNotebook")
        self.notebook.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_change)

        # Definición de herramientas
        tools = [
            ("Cifrado César", self._setup_cesar_ui),
            ("Cifrado Afín", self._setup_afin_ui),
            ("Euclides y MCD", self._setup_euclides_ui),
            ("Inverso Modular", self._setup_inverso_ui),
            ("T. Chino Residuo", self._setup_tcr_ui),
            None, # Separador
            ("C. Vigenère", self._setup_vigenere_ui),
            ("One-Time Pad", self._setup_otp_ui),
            ("Criptosistema RSA", self._setup_rsa_ui)
        ]

        # Mapeo de índices de notebook a índices de botones (saltando el separador)
        self.button_map = {i if i < 5 else i-1: i for i in range(len(tools))}

        for i, tool_info in enumerate(tools):
            if tool_info is None:
                ttk.Separator(sidebar).pack(fill='x', padx=20, pady=10)
                continue
            
            name, setup_func = tool_info
            
            # Crear botón de navegación
            btn_index = i if i < 5 else i -1 # Ajustar índice por el separador
            btn = ttk.Button(sidebar, text=name, command=lambda index=len(self.notebook.tabs()): self.notebook.select(index))
            btn.pack(fill='x', padx=20, pady=2)
            self.nav_buttons[btn_index] = btn
            
            # Crear el frame para la herramienta (la "pestaña")
            tool_frame = ttk.Frame(self.notebook)
            self.notebook.add(tool_frame, text=name)
            
            # poblar la pestaña con sus controles y salidas
            controls, output = self._create_base_panels(tool_frame)
            ttk.Label(controls, text=name, style="Header.TLabel").pack(pady=(0, 20), padx=20, anchor='w')
            setup_func(controls, output)
            
        self._on_tab_change() # Seleccionar el primer botón

    def _on_tab_change(self, event=None):
        current_index = self.notebook.index(self.notebook.select())
        for index, button in self.nav_buttons.items():
            button.state(["pressed"] if index == current_index else ["!pressed"])

    def _create_base_panels(self, parent):
        parent.grid_columnconfigure(1, weight=1)
        parent.grid_rowconfigure(0, weight=1)
        
        controls = ttk.Frame(parent, style="Card.TFrame", width=380)
        controls.grid(row=0, column=0, sticky="ns", pady=10, padx=(10,5))
        controls.pack_propagate(False)

        output = ttk.Frame(parent, style="TFrame")
        output.grid(row=0, column=1, sticky="nsew", pady=10, padx=(5,10))
        output.grid_rowconfigure(2, weight=1)
        output.grid_columnconfigure(0, weight=1)
        
        return controls, output

    # --- Constructores de UI para cada Herramienta ---

    def _setup_cesar_ui(self, controls, output):
        ttk.Label(controls, text="Texto:", style="Card.TLabel", font=self.font_bold).pack(anchor='w', padx=20)
        text_in = tk.Text(controls, height=5, font=self.font_normal, relief='solid', borderwidth=1, highlightthickness=1)
        text_in.pack(fill='x', padx=20, pady=5)
        text_in.insert("1.0", "HELLO WORLD")
        
        ttk.Label(controls, text="Shift (b):", style="Card.TLabel", font=self.font_bold).pack(anchor='w', padx=20, pady=(10,0))
        b_in = ttk.Entry(controls); b_in.pack(fill='x', padx=20, pady=5); b_in.insert(0, "3")

        mode, result_text, steps_tree = self._common_widgets(controls, output, ["Entrada", "Cálculo", "Salida"])

        def execute():
            try:
                b_val = int(b_in.get())
                if b_val < 0:
                    raise ValueError("El shift 'b' no puede ser negativo.")
                res = CriptoMath.caesar_cipher(text_in.get("1.0", "end-1c"), b_val, mode.get()=='dec')
                result_text.config(text=res['result'])
                self._update_tree(steps_tree, res['steps'])
            except ValueError as e: 
                messagebox.showerror("Error de Entrada", f"Valor inválido para 'b'.\n{e}")
            except Exception as e: 
                messagebox.showerror("Error", str(e))
            
        ttk.Button(controls, text="Ejecutar", command=execute).pack(fill='x', side='bottom', padx=20, pady=20)

    def _setup_afin_ui(self, controls, output):
        ttk.Label(controls, text="Texto:", style="Card.TLabel", font=self.font_bold).pack(anchor='w', padx=20)
        text_in = tk.Text(controls, height=5, font=self.font_normal, relief='solid', borderwidth=1, highlightthickness=1)
        text_in.pack(fill='x', padx=20, pady=5); text_in.insert("1.0", "AFFINE CIPHER")
        
        ttk.Label(controls, text="Parámetro (a):", style="Card.TLabel", font=self.font_bold).pack(anchor='w', padx=20, pady=(10,0))
        coprimes = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
        a_in = ttk.Combobox(controls, values=coprimes, state="readonly"); a_in.pack(fill='x', padx=20, pady=5); a_in.set(5)
        
        ttk.Label(controls, text="Parámetro (b):", style="Card.TLabel", font=self.font_bold).pack(anchor='w', padx=20, pady=(10,0))
        b_in = ttk.Entry(controls); b_in.pack(fill='x', padx=20, pady=5); b_in.insert(0, "8")
        
        mode, result_text, steps_tree = self._common_widgets(controls, output, ["Entrada", "Cálculo", "Salida"])

        def execute():
            try:
                b_val = int(b_in.get())
                if b_val < 0:
                    raise ValueError("El parámetro 'b' no puede ser negativo.")
                res = CriptoMath.affine_cipher(text_in.get("1.0", "end-1c"), int(a_in.get()), b_val, mode.get()=='dec')
                result_text.config(text=res['result'])
                self._update_tree(steps_tree, res['steps'])
            except ValueError as e: 
                messagebox.showerror("Error de Entrada", f"Valor inválido para 'b'.\n{e}")
            except Exception as e: 
                messagebox.showerror("Error", str(e))
        
        ttk.Button(controls, text="Ejecutar", command=execute).pack(fill='x', side='bottom', padx=20, pady=20)

    def _setup_vigenere_ui(self, controls, output):
        ttk.Label(controls, text="Texto:", style="Card.TLabel", font=self.font_bold).pack(anchor='w', padx=20)
        text_in = tk.Text(controls, height=5, font=self.font_normal, relief='solid', borderwidth=1, highlightthickness=1)
        text_in.pack(fill='x', padx=20, pady=5); text_in.insert("1.0", "ATTACK AT DAWN")

        ttk.Label(controls, text="Llave (k):", style="Card.TLabel", font=self.font_bold).pack(anchor='w', padx=20, pady=(10,0))
        key_in = ttk.Entry(controls); key_in.pack(fill='x', padx=20, pady=5); key_in.insert(0, "LEMON")

        mode, result_text, steps_tree = self._common_widgets(controls, output, ["Entrada", "Llave", "Shift", "Cálculo", "Salida"])

        def execute():
            try:
                res = CriptoMath.vigenere_cipher(text_in.get("1.0", "end-1c"), key_in.get(), mode.get()=='dec')
                result_text.config(text=res['result'])
                self._update_tree(steps_tree, res['steps'])
            except Exception as e: messagebox.showerror("Error", str(e))
        
        ttk.Button(controls, text="Ejecutar", command=execute).pack(fill='x', side='bottom', padx=20, pady=20)

    def _setup_otp_ui(self, controls, output):
        ttk.Label(controls, text="Mensaje:", style="Card.TLabel", font=self.font_bold).pack(anchor='w', padx=20)
        text_in = tk.Text(controls, height=5, font=self.font_normal, relief='solid', borderwidth=1, highlightthickness=1)
        text_in.pack(fill='x', padx=20, pady=5); text_in.insert("1.0", "SECRET MESSAGE")

        ttk.Label(controls, text="Llave (k):", style="Card.TLabel", font=self.font_bold).pack(anchor='w', padx=20, pady=(10,0))
        key_in = ttk.Entry(controls); key_in.pack(fill='x', padx=20, pady=5)
        
        val_label = ttk.Label(controls, font=self.font_small, style="Card.TLabel"); val_label.pack(anchor='w', padx=20)

        exec_btn = ttk.Button(controls, text="Ejecutar")
        
        def validate(*args):
            text_len = len(''.join(filter(str.isalpha, text_in.get("1.0", "end-1c"))))
            key_len = len(''.join(filter(str.isalpha, key_in.get())))
            if text_len == 0 and key_len == 0:
                val_label.config(text="")
                exec_btn.config(state="disabled")
                return
            if text_len == key_len:
                val_label.config(text=f"Correcto: Longitudes coinciden ({text_len})", style="Success.TLabel")
                exec_btn.config(state="normal")
            else:
                val_label.config(text=f"Error: Longitudes deben ser iguales (M: {text_len}, K: {key_len})", style="Error.TLabel")
                exec_btn.config(state="disabled")
        
        text_in.bind("<KeyRelease>", validate); key_in.bind("<KeyRelease>", validate)
        
        def generate_key():
            text = ''.join(filter(str.isalpha, text_in.get("1.0", "end-1c")))
            new_key = ''.join(random.choice(CriptoMath.ALPHABET) for _ in range(len(text)))
            key_in.delete(0, tk.END); key_in.insert(0, new_key); validate()
            
        ttk.Button(controls, text="Generar Llave Aleatoria", command=generate_key).pack(fill='x', padx=20, pady=10)

        mode, result_text, steps_tree = self._common_widgets(controls, output, ["Entrada", "Llave", "Shift", "Cálculo", "Salida"])

        def execute():
            try:
                res = CriptoMath.one_time_pad_cipher(text_in.get("1.0", "end-1c"), key_in.get(), mode.get()=='dec')
                result_text.config(text=res['result']); self._update_tree(steps_tree, res['steps'])
            except Exception as e: messagebox.showerror("Error", str(e))
        
        exec_btn.config(command=execute); exec_btn.pack(fill='x', side='bottom', padx=20, pady=20)
        validate()

    def _setup_rsa_ui(self, controls, output):
        # Frame de Generación
        gen_frame = ttk.Frame(controls, style="Card.TFrame")
        gen_frame.pack(fill='x', padx=20, pady=(0,10))
        ttk.Label(gen_frame, text="1. Generación de Claves", style="Card.TLabel", font=self.font_bold).pack(anchor='w',pady=5)
        
        p_in = self._create_labeled_entry(gen_frame, "Primo (p):", "61")
        q_in = self._create_labeled_entry(gen_frame, "Primo (q):", "53")
        e_in = self._create_labeled_entry(gen_frame, "Exponente (e):", "17")
        val_label = ttk.Label(gen_frame, font=self.font_small, style="Card.TLabel"); val_label.pack(anchor='w', pady=5)
        
        gen_btn = ttk.Button(gen_frame, text="Generar y Validar Claves")
        gen_btn.pack(fill='x', pady=5)
        
        pub_key_out = self._create_labeled_entry(gen_frame, "Clave Pública (N,e):", "", readonly=True)
        priv_key_out = self._create_labeled_entry(gen_frame, "Clave Privada (d):", "", readonly=True)

        # Frame de Operación
        op_frame = ttk.Frame(controls, style="Card.TFrame")
        op_frame.pack(fill='x', expand=True, padx=20)
        ttk.Label(op_frame, text="2. Operación", style="Card.TLabel", font=self.font_bold).pack(anchor='w', pady=5)
        
        ttk.Label(op_frame, text="Mensaje / Cifrado:", style="Card.TLabel").pack(anchor='w')
        text_in = tk.Text(op_frame, height=4, font=self.font_normal, relief='solid', borderwidth=1, highlightthickness=1)
        text_in.pack(fill='x', pady=5); text_in.insert("1.0", "RSA ENCRYPTED")

        mode, result_text, steps_tree = self._common_widgets(op_frame, output, ["Entrada", "Cálculo", "Resultado"], show_mode=True)
        exec_btn = ttk.Button(controls, text="Ejecutar", state='disabled')
        exec_btn.pack(fill='x', side='bottom', padx=20, pady=20)
        
        rsa_params = {}
        def validate_and_generate():
            try:
                p, q, e = int(p_in.get()), int(q_in.get()), int(e_in.get())
                if not CriptoMath.is_prime(p): raise ValueError(f"p={p} no es primo.")
                if not CriptoMath.is_prime(q): raise ValueError(f"q={q} no es primo.")
                if p == q: raise ValueError("p y q no pueden ser iguales.")
                phi_N = (p-1)*(q-1)
                if not (1 < e < phi_N): raise ValueError(f"e={e} debe estar entre 1 y φ(N)={phi_N}.")
                if CriptoMath.mcd(e, phi_N) != 1: raise ValueError(f"e={e} no es coprimo con φ(N)={phi_N}.")
                
                val_label.config(text="✓ Parámetros válidos.", style="Success.TLabel")
                N = p * q
                d = CriptoMath.modinv(e, phi_N)
                rsa_params.update({'N': N, 'e': e, 'd': d})
                
                self._set_readonly_entry(pub_key_out, f"({N}, {e})")
                self._set_readonly_entry(priv_key_out, str(d))
                exec_btn.config(state='normal')

            except Exception as ex:
                val_label.config(text=f"Error: {ex}", style="Error.TLabel")
                self._set_readonly_entry(pub_key_out, "")
                self._set_readonly_entry(priv_key_out, "")
                exec_btn.config(state='disabled')

        gen_btn.config(command=validate_and_generate)
        for entry in [p_in, q_in, e_in]:
            entry.bind("<KeyRelease>", lambda e: validate_and_generate())

        def execute():
            try:
                key = rsa_params['e'] if mode.get() == 'enc' else rsa_params['d']
                res = CriptoMath.rsa_cipher(text_in.get("1.0", "end-1c"), rsa_params['N'], key, mode.get())
                result_text.config(text=res['result']); self._update_tree(steps_tree, res['steps'])
            except Exception as ex: messagebox.showerror("Error", str(ex))
            
        exec_btn.config(command=execute)
        validate_and_generate()
        
    def _setup_euclides_ui(self, controls, output):
        a_in = self._create_labeled_entry(controls, "Entero (a):", "391")
        b_in = self._create_labeled_entry(controls, "Entero (b):", "299")
        
        _, result_text, steps_tree = self._common_widgets(controls, output, ["Paso de División", "Identidad de Bézout"], show_mode=False)
        result_text.config(wraplength=350, justify='left')

        def execute():
            try:
                res = CriptoMath.euclides_algorithm(int(a_in.get()), int(b_in.get()))
                result_text.config(text=res['result']); self._update_tree(steps_tree, res['steps'])
            except Exception as e: messagebox.showerror("Error", str(e))
        
        ttk.Button(controls, text="Calcular", command=execute).pack(fill='x', side='bottom', padx=20, pady=20)
        
    def _setup_inverso_ui(self, controls, output):
        a_in = self._create_labeled_entry(controls, "Entero (a):", "17")
        m_in = self._create_labeled_entry(controls, "Módulo (m):", "20")
        val_label = ttk.Label(controls, font=self.font_small, style="Card.TLabel"); val_label.pack(anchor='w', padx=20)
        
        exec_btn = ttk.Button(controls, text="Calcular Inverso")

        def validate(*args):
            try:
                a, m = int(a_in.get()), int(m_in.get())
                if m <= 1: raise ValueError("Módulo debe ser > 1.")
                g = CriptoMath.mcd(a,m)
                if g == 1:
                    val_label.config(text=f"✓ mcd({a},{m}) = 1. El inverso existe.", style="Success.TLabel")
                    exec_btn.config(state="normal")
                else:
                    val_label.config(text=f"✖ mcd({a},{m}) = {g}. NO existe.", style="Error.TLabel")
                    exec_btn.config(state="disabled")
            except (ValueError, TypeError) as e:
                val_label.config(text=f"Error: {e}", style="Error.TLabel")
                exec_btn.config(state="disabled")

        a_in.bind("<KeyRelease>", validate); m_in.bind("<KeyRelease>", validate)
        
        _, result_text, steps_tree = self._common_widgets(controls, output, ["Paso", "Cálculo", "Resultado"], show_mode=False)

        def execute():
            try:
                a, m = int(a_in.get()), int(m_in.get())
                inv = CriptoMath.modinv(a, m)
                g, x, y = CriptoMath.egcd(a,m)
                steps = [("Verificar", f"mcd({a},{m})", g), ("Euclides Ext.", f"{a}({x})+{m}({y})={g}", f"x={x}"), ("Inverso", f"x mod m", inv)]
                result_text.config(text=f"{a}⁻¹ ≡ {inv} (mod {m})")
                self._update_tree(steps_tree, steps)
            except Exception as e: messagebox.showerror("Error", str(e))
        
        exec_btn.config(command=execute); exec_btn.pack(fill='x', side='bottom', padx=20, pady=20)
        validate()
        
    def _setup_tcr_ui(self, controls, output):
        ttk.Label(controls, text="Sistema de Congruencias:", style="Card.TLabel", font=self.font_bold).pack(anchor='w', padx=20)
        
        rows_frame = ttk.Frame(controls, style="Card.TFrame"); rows_frame.pack(fill='x', padx=20, pady=5)
        val_label = ttk.Label(controls, font=self.font_small, style="Card.TLabel"); val_label.pack(anchor='w', padx=20)
        tcr_rows = []

        def validate_tcr():
            try:
                # CORRECCIÓN: Ahora se obtiene de la tupla correcta
                moduli = [int(n.get()) for f, r, n in tcr_rows if n.get()]
                if len(moduli) < 2:
                    val_label.config(text="")
                    return True
                
                for i in range(len(moduli)):
                    if moduli[i] <= 1: raise ValueError(f"Módulo {moduli[i]} debe ser > 1.")
                    for j in range(i + 1, len(moduli)):
                        if CriptoMath.mcd(moduli[i], moduli[j]) != 1:
                            raise ValueError(f"mcd({moduli[i]}, {moduli[j]}) ≠ 1")
                val_label.config(text="✓ Módulos son coprimos en pares.", style="Success.TLabel")
                return True
            except Exception as e:
                val_label.config(text=f"Error: {e}", style="Error.TLabel")
                return False

        def remove_row(row_tuple):
            if len(tcr_rows) <= 2:
                messagebox.showwarning("Aviso", "Se requieren al menos dos congruencias.")
                return
            frame, r_entry, n_entry = row_tuple
            tcr_rows.remove(row_tuple)
            frame.destroy()
            validate_tcr()

        def add_row(r_val="", n_val=""):
            row_frame = ttk.Frame(rows_frame, style="Card.TFrame")
            row_frame.pack(fill='x', pady=2)
            
            ttk.Label(row_frame, text="n ≡", style="Card.TLabel").pack(side='left', padx=2)
            r = ttk.Entry(row_frame, width=5); r.pack(side='left'); r.insert(0, r_val)
            ttk.Label(row_frame, text="(mod", style="Card.TLabel").pack(side='left', padx=2)
            n = ttk.Entry(row_frame, width=5); n.pack(side='left'); n.insert(0, n_val)
            ttk.Label(row_frame, text=")", style="Card.TLabel").pack(side='left', padx=2)
            
            # CORRECCIÓN: La tupla ahora incluye el frame para poder eliminarlo
            row_tuple = (row_frame, r, n)
            remove_btn = ttk.Button(row_frame, text="-", width=2, command=lambda t=row_tuple: remove_row(t))
            remove_btn.pack(side='right', padx=(5,0))

            r.bind("<KeyRelease>", lambda e: validate_tcr())
            n.bind("<KeyRelease>", lambda e: validate_tcr())
            
            tcr_rows.append(row_tuple)
            validate_tcr()
            
        ttk.Button(controls, text="Añadir Congruencia", command=lambda: add_row()).pack(fill='x', padx=20, pady=5)
        add_row("2", "3"); add_row("3", "5"); add_row("2", "7")
        
        _, result_text, steps_tree = self._common_widgets(controls, output, ["Paso", "Cálculo", "Resultado"], show_mode=False)

        def execute():
            if not validate_tcr():
                messagebox.showerror("Error de Validación", "Revise los módulos antes de continuar.")
                return
            try:
                congruences = [(int(r.get()), int(n.get())) for f, r, n in tcr_rows]
                res = CriptoMath.chinese_remainder_theorem(congruences)
                result_text.config(text=res['result']); self._update_tree(steps_tree, res['steps'])
            except Exception as e: messagebox.showerror("Error", str(e))

        ttk.Button(controls, text="Resolver Sistema", command=execute).pack(fill='x', side='bottom', padx=20, pady=20)


    # --- Métodos de Ayuda para UI ---

    def _common_widgets(self, controls, output, tree_cols, show_mode=True):
        mode = tk.StringVar(value="enc")
        if show_mode:
            mode_frame = ttk.Frame(controls, style="Card.TFrame")
            mode_frame.pack(anchor='w', padx=20, pady=10)
            ttk.Radiobutton(mode_frame, text="Encriptar", variable=mode, value="enc").pack(side='left')
            ttk.Radiobutton(mode_frame, text="Desencriptar", variable=mode, value="dec").pack(side='left', padx=10)
        
        ttk.Label(output, text="Resultado Final:", font=self.font_bold).pack(anchor='w', padx=10, pady=(0,5))
        result_text = ttk.Label(output, text="-", style="Result.TLabel"); result_text.pack(anchor='w', padx=10, pady=(0,10))
        ttk.Label(output, text="Proceso Matemático:", font=self.font_bold).pack(anchor='w', padx=10, pady=(10,5))
        
        tree_frame = ttk.Frame(output); tree_frame.pack(fill='both', expand=True, padx=10, pady=(0,10))
        tree = self._create_treeview(tree_frame, tree_cols)
        
        return mode, result_text, tree

    def _create_labeled_entry(self, parent, label_text, default_value, readonly=False):
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.pack(fill='x', padx=10, pady=2)
        ttk.Label(frame, text=label_text, style="Card.TLabel", width=15).pack(side='left')
        entry = ttk.Entry(frame, state='readonly' if readonly else 'normal')
        entry.pack(side='left', fill='x', expand=True)
        if default_value: entry.insert(0, default_value)
        return entry
        
    def _set_readonly_entry(self, entry, value):
        entry.config(state='normal')
        entry.delete(0, tk.END)
        entry.insert(0, value)
        entry.config(state='readonly')

    def _create_treeview(self, parent, columns):
        parent.grid_rowconfigure(0, weight=1); parent.grid_columnconfigure(0, weight=1)
        tree = ttk.Treeview(parent, columns=columns, show="headings")
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150, anchor='w')
        
        vsb = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        return tree

    def _update_tree(self, tree, data):
        tree.delete(*tree.get_children())
        for row in data:
            tree.insert("", tk.END, values=row)

if __name__ == "__main__":
    app = CriptoSuiteApp()
    app.mainloop()

