"""
genkey.py - Comando --genkey: genera el par RSA y lo guarda en el KeyStore.
"""

import os
from getpass import getpass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from keystore import KeystoreError, cargar_keystore, guardar_keystore


def pedir_dn():
    """
    Pide por teclado los datos del titular (Distinguished Name).

    Entradas:
        Ninguna (los datos se piden con input()).
    Salida:
        dict: con las claves CN, OU, O, L, ST y C.
    """
    dn = {}
    dn["CN"] = input("Nombre y apellidos (CN): ").strip()
    dn["OU"] = input("Unidad organizativa (OU): ").strip()
    dn["O"] = input("Organización (O): ").strip()
    dn["L"] = input("Ciudad o localidad (L): ").strip()
    dn["ST"] = input("Provincia o estado (ST): ").strip()

    # El código de país es opcional; si se escribe, debe tener 2 letras (ej: ES)
    pais = input("Código de país de 2 letras (C, opcional): ").strip().upper()
    while pais != "" and len(pais) != 2:
        print("El código de país debe tener 2 letras, por ejemplo ES (o déjalo vacío).")
        pais = input("Código de país de 2 letras (C, opcional): ").strip().upper()
    dn["C"] = pais

    return dn


def comando_genkey(ruta):
    """
    Implementa --genkey: crea un par RSA 2048 y lo guarda en el KeyStore.

    Entradas:
        ruta (str): ruta del archivo del KeyStore.
    Salida:
        Ninguna. Imprime el resultado por pantalla y guarda el archivo.
    Errores (KeystoreError):
        - Contraseña del almacén incorrecta.
        - Alias duplicado o vacío.
    """
    password = getpass("Contraseña del KeyStore: ")
    if password == "":
        raise KeystoreError("La contraseña del KeyStore no puede estar vacía.")

    # Si el almacén existe se abre; si no, se crea uno vacío nuevo
    if os.path.exists(ruta):
        datos = cargar_keystore(ruta, password)
    else:
        print("El almacén no existe, se creará uno nuevo.")
        datos = {"aliases": {}}

    alias = input("Alias: ").strip()
    if alias == "":
        raise KeystoreError("El alias no puede estar vacío.")
    if alias in datos["aliases"]:
        raise KeystoreError("El alias '" + alias + "' ya existe en el almacén.")

    password_alias = getpass("Contraseña del alias: ")
    if password_alias == "":
        raise KeystoreError("La contraseña del alias no puede estar vacía.")

    dn = pedir_dn()

    print("Generando par de claves RSA de 2048 bits...")
    clave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # La clave privada se guarda en PEM cifrada con la contraseña del alias
    pem_privada = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password_alias.encode("utf-8")
        ),
    )

    datos["aliases"][alias] = {
        "dn": dn,
        "clave_privada": pem_privada.decode("ascii"),
    }

    guardar_keystore(ruta, password, datos)
    print("Par de claves '" + alias + "' guardado en " + ruta + ".")
