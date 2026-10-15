"""
certreq.py - Comando --certreq: genera la solicitud de firma CSR (PERSONA B).
"""

from getpass import getpass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from keystore import KeystoreError, cargar_keystore


def construir_nombre(dn):
    """
    Convierte el diccionario del DN en un objeto Name de la librería cryptography.

    Entradas:
        dn (dict): datos del titular (CN, OU, O, L, ST, C).
    Salida:
        x509.Name: nombre listo para usar en el CSR. Los campos vacíos se omiten.
    """
    equivalencias = [
        ("CN", NameOID.COMMON_NAME),
        ("OU", NameOID.ORGANIZATIONAL_UNIT_NAME),
        ("O", NameOID.ORGANIZATION_NAME),
        ("L", NameOID.LOCALITY_NAME),
        ("ST", NameOID.STATE_OR_PROVINCE_NAME),
        ("C", NameOID.COUNTRY_NAME),
    ]
    atributos = []
    for campo, oid in equivalencias:
        if dn.get(campo, "") != "":
            atributos.append(x509.NameAttribute(oid, dn[campo]))
    return x509.Name(atributos)


def comando_certreq(ruta):
    """
    Implementa --certreq: genera un archivo .csr en formato PEM.

    Entradas:
        ruta (str): ruta del archivo del KeyStore.
    Salida:
        Ninguna. Crea el archivo <alias>.csr y lo muestra por pantalla.
    Errores (KeystoreError):
        - Almacén inexistente o dañado.
        - Contraseña del almacén o del alias incorrecta.
        - El alias no existe.
    """
    password = getpass("Contraseña del KeyStore: ")
    datos = cargar_keystore(ruta, password)

    alias = input("Alias: ").strip()
    if alias not in datos["aliases"]:
        raise KeystoreError("El alias '" + alias + "' no existe en el almacén.")

    password_alias = getpass("Contraseña del alias: ")
    entrada = datos["aliases"][alias]

    # Si la contraseña del alias es mala, load_pem_private_key lanza ValueError
    try:
        clave_privada = serialization.load_pem_private_key(
            entrada["clave_privada"].encode("ascii"),
            password=password_alias.encode("utf-8"),
        )
    except ValueError:
        raise KeystoreError("Contraseña del alias incorrecta.")

    # Se construye y se firma la solicitud con la clave privada
    nombre = construir_nombre(entrada["dn"])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(nombre)
        .sign(clave_privada, hashes.SHA256())
    )
    pem_csr = csr.public_bytes(serialization.Encoding.PEM)

    archivo_salida = alias + ".csr"
    with open(archivo_salida, "wb") as archivo:
        archivo.write(pem_csr)

    print("Solicitud de certificado guardada en " + archivo_salida + ":")
    print(pem_csr.decode("ascii"))
