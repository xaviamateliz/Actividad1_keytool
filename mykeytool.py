"""
mykeytool.py - Simulador en Python de la herramienta keytool de Java.

Comandos:
    python3 mykeytool.py --help        Muestra la ayuda
    python3 mykeytool.py --genkey      Genera un par de claves RSA 2048 y lo guarda en el KeyStore
    python3 mykeytool.py --certreq     Genera una solicitud de firma (CSR) en formato PEM

Dependencia:
    pip install cryptography
"""

import argparse
import sys

from certreq import comando_certreq
from genkey import comando_genkey
from keystore import ARCHIVO_KEYSTORE, KeystoreError


def main():
    """
    Punto de entrada: lee los argumentos y ejecuta el comando elegido.

    Entradas:
        Argumentos de la terminal (--genkey, --certreq, --keystore).
    Salida:
        Ninguna. Termina con código 1 si ocurre un error controlado.
    """
    parser = argparse.ArgumentParser(
        description="Simulador de keytool de Java hecho en Python."
    )
    grupo = parser.add_mutually_exclusive_group(required=True)
    grupo.add_argument(
        "--genkey",
        "--genkeypair",
        dest="genkey",
        action="store_true",
        help="Genera un par de claves RSA 2048 y lo guarda en el KeyStore",
    )
    grupo.add_argument(
        "--certreq",
        action="store_true",
        help="Genera una solicitud de firma de certificado (CSR) en formato PEM",
    )
    parser.add_argument(
        "--keystore",
        default=ARCHIVO_KEYSTORE,
        help="Archivo del KeyStore (por defecto: " + ARCHIVO_KEYSTORE + ")",
    )
    args = parser.parse_args()

    try:
        if args.genkey:
            comando_genkey(args.keystore)
        elif args.certreq:
            comando_certreq(args.keystore)
    except KeystoreError as error:
        print("Error: " + str(error))
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperación cancelada.")
        sys.exit(1)


if __name__ == "__main__":
    main()
