"""
exportkey.py - Comando --exportkey: exporta la clave privada de un alias a un archivo .pem (AMPLIACIÓN).
"""

import os
from getpass import getpass

from cryptography.hazmat.primitives import serialization

from keystore import KeystoreError, cargar_keystore


def comando_exportkey(ruta):
    """
    Implementa --exportkey: saca la clave privada de un alias del KeyStore
    y la guarda en un archivo <alias>.pem (sigue cifrada con la contraseña del alias).

    Entradas:
        ruta (str): ruta del archivo del KeyStore.
    Salida:
        Ninguna. Crea el archivo <alias>.pem e imprime el resultado por pantalla.
    Errores (KeystoreError):
        - El almacén no existe, está dañado o su contraseña es incorrecta.
        - El alias no existe.
        - La contraseña del alias es incorrecta.
        - El archivo .pem de salida ya existe.
    """
    password = getpass("Contraseña del KeyStore: ")
    datos = cargar_keystore(ruta, password)

    alias = input("Alias: ").strip()
    if alias not in datos["aliases"]:
        raise KeystoreError("El alias '" + alias + "' no existe en el almacén.")

    password_alias = getpass("Contraseña del alias: ")
    pem_privada = datos["aliases"][alias]["clave_privada"]

    # Comprobamos la contraseña del alias intentando abrir la clave privada
    try:
        serialization.load_pem_private_key(
            pem_privada.encode("ascii"),
            password=password_alias.encode("utf-8"),
        )
    except (ValueError, TypeError):
        raise KeystoreError("Contraseña del alias incorrecta.")

    # No sobrescribimos un archivo que ya exista
    archivo_salida = alias + ".pem"
    if os.path.exists(archivo_salida):
        raise KeystoreError("El archivo '" + archivo_salida + "' ya existe.")

    with open(archivo_salida, "w") as archivo:
        archivo.write(pem_privada)

    print("Clave privada del alias '" + alias + "' exportada a " + archivo_salida + ".")
