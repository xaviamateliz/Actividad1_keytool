"""
keystore.py - Persistencia cifrada del KeyStore (PERSONA B).
"""

import base64
import json
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Nombre del archivo donde se guarda el almacén por defecto
ARCHIVO_KEYSTORE = "keystore.ks"


class KeystoreError(Exception):
    """Error propio del programa (alias duplicado, contraseña mala, etc.)."""
    pass


def derivar_clave(password, salt):
    """
    Convierte una contraseña en una clave de cifrado para Fernet.

    Entradas:
        password (str): contraseña escrita por el usuario.
        salt (bytes): 16 bytes aleatorios que se guardan junto al archivo.
    Salida:
        bytes: clave de 32 bytes en base64, lista para usar con Fernet.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def guardar_keystore(ruta, password, datos):
    """
    Cifra el diccionario del almacén y lo escribe en el archivo.

    Entradas:
        ruta (str): ruta del archivo del KeyStore.
        password (str): contraseña del KeyStore.
        datos (dict): contenido del almacén, con la forma {"aliases": {...}}.
    Salida:
        Ninguna. Crea o sobrescribe el archivo.
    """
    salt = os.urandom(16)
    clave = derivar_clave(password, salt)
    texto = json.dumps(datos).encode("utf-8")
    token = Fernet(clave).encrypt(texto)
    with open(ruta, "wb") as archivo:
        archivo.write(salt + token)


def cargar_keystore(ruta, password):
    """
    Lee el archivo del KeyStore, lo descifra y devuelve su contenido.

    Entradas:
        ruta (str): ruta del archivo del KeyStore.
        password (str): contraseña del KeyStore.
    Salida:
        dict: contenido del almacén, con la forma {"aliases": {...}}.
    Errores (KeystoreError):
        - El archivo no existe.
        - El archivo está dañado.
        - La contraseña es incorrecta.
    """
    if not os.path.exists(ruta):
        raise KeystoreError("El almacén '" + ruta + "' no existe.")

    with open(ruta, "rb") as archivo:
        contenido = archivo.read()

    # Los primeros 16 bytes son el salt; si hay menos, el archivo está roto
    if len(contenido) <= 16:
        raise KeystoreError("El almacén está dañado.")

    salt = contenido[:16]
    token = contenido[16:]
    clave = derivar_clave(password, salt)

    try:
        texto = Fernet(clave).decrypt(token)
    except InvalidToken:
        raise KeystoreError("Contraseña del almacén incorrecta (o archivo dañado).")

    try:
        datos = json.loads(texto.decode("utf-8"))
    except ValueError:
        raise KeystoreError("El almacén está dañado.")

    if "aliases" not in datos:
        raise KeystoreError("El almacén está dañado.")

    return datos
