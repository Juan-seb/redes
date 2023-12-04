from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii
import tkinter as tk

encrypt_msg=''
decrypt_msg=''
text_encrypt=''

curve = registry.get_curve("secp256r1")

# Esta linea de codigo selecciona un numero aleatorio entre [0..n]
# n -> Orden la curva
privKey = secrets.randbelow(curve.field.n)
# curve.g obtiene el punto generador de la curva, previamente seleccionado
pubKey = privKey * curve.g

# La función toma un punto (clave publica) y la converte a un 256 bit
def point_to_256_bit(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

# Encriptamos el texto usando el metodo AES, aqui la secret key es la clave publica
# obtenida con el algoritmo de curva eliptica
def AES_encrypt(msg, secretKey):
    cipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = cipher.encrypt_and_digest(msg)
    return (ciphertext, cipher.nonce, authTag)

# Desencriptamos el texto, la secret key que recibe sera la llave privada
def AES_decrypt(ciphertext, nonce, authTag, secretKey):
    cipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

# Metodo que usamos para encriptar con ayuda de la criptografia de curva eliptica
def encrypt_ECC(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    # Creamos la llave compartida, usando la llave publica.
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = point_to_256_bit(sharedECCKey)
    # Encriptamos el texto con AES
    ciphertext, nonce, authTag = AES_encrypt(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g

    return (ciphertext, nonce, authTag, ciphertextPubKey)

# Metodo que usamos para desencriptar con ayuda de la criptografia de curva eliptica
def decrypt_ECC(encryptedMessage, privKey):
    # De encryptedMessage obtenemos estos valores que definimos en el metodo encrypt_ECC
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMessage
    # Obtenemos la clave compartida, usamos la llave privada para poder obtenerla.
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = point_to_256_bit(sharedECCKey)
    # Desencriptamos usando la función definida anteriormente.
    plaintext = AES_decrypt(ciphertext, nonce, authTag, secretKey)

    return plaintext

def button_encrypt_func():
    global encrypt_msg
    global text_encrypt

    message = text_input.get().encode("utf-8")
    encrypt_text_entry.insert(tk.END, '')

    encrypt_msg=encrypt_ECC(message,pubKey)
    (ciphertext, nonce, authTag, ciphertextPubKey) = encrypt_msg
    text_encrypt=binascii.hexlify(ciphertext)

    priv_key_label.config(text=f'Clave Privada:\n{privKey}')
    public_key_label.config(text=f'Clave Pública:\n{point_to_256_bit(pubKey)}')
    encrypt_text_entry.insert(tk.END, f'{text_encrypt}')

def button_decrypt_func():
    decrypt_msg = decrypt_ECC(encrypt_msg,privKey)
    decrypt_text_label.config(text=f'Texto desencriptado:\n{decrypt_msg}')


# Configuracion de la interfaz
root = tk.Tk()
root.title("Aplicativo de Encriptación")
root.geometry("700x400")  # Dimensiones interfaz

# Etiqueta y entrada de texto para ingresar el texto a encriptar
label_text = tk.Label(root, text="Texto a Encriptar:")
label_text.pack()
text_input = tk.Entry(root, width=50)
text_input.pack()

# Botones para encriptar y desencriptar
button_decrypt = tk.Button(root, text="Desencriptar", command=button_decrypt_func)
button_decrypt.pack(side=tk.BOTTOM)
button_encrypt = tk.Button(root, text="Encriptar", command=button_encrypt_func)
button_encrypt.pack(side=tk.BOTTOM)

# Etiquetas para mostrar la clave privada, clave pública y el texto encriptado
priv_key_label = tk.Label(root, text="Clave Privada:", wraplength=400, justify="left")
priv_key_label.pack(anchor="w", padx=10, pady=(0, 10))
public_key_label = tk.Label(root, text="Clave publica:", wraplength=400, justify="left")
public_key_label.pack(anchor="w", padx=10, pady=(0, 10))

# Etiqueta para mostrar el texto desencriptado
decrypt_text_label = tk.Label(root, text="Texto desencriptado:", wraplength=400, justify="left") 
decrypt_text_label.pack(anchor="w", padx=10, pady=(0, 10))

# Etiqueta para mostrar el texto desencriptado
encrypt_text_label = tk.Label(root, text="Texto encriptado:", wraplength=400, justify="left") 
encrypt_text_label.pack(anchor="w", padx=10, pady=(0, 10))

encrypt_text_entry = tk.Entry(root, width=300) 
encrypt_text_entry.pack(anchor="w", padx=10, pady=(0, 10))

# Iniciar el bucle principal de la interfaz
root.mainloop()
