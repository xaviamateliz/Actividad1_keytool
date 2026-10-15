# Práctica Keytool en Python

**Integrantes:** Xavi Amate / Saul Martin

Simulador en Python de la herramienta `keytool` de Java.

## Instalación

```bash
pip install cryptography
```

## Uso

```bash
python3 mykeytool.py --help
python3 mykeytool.py --genkey      # (también vale --genkeypair)
python3 mykeytool.py --certreq
python3 mykeytool.py --genkey --keystore otro.ks
```

_Añadir capturas o ejemplos de consola._

## Estructura

| Archivo | Contenido |
|---|---|
| `mykeytool.py` | CLI con argparse |
| `genkey.py` | Generación del par RSA 2048 y datos del titular |
| `keystore.py` | Cifrado y persistencia del almacén |
| `certreq.py` | Generación del CSR en PEM |

## Matriz de pruebas

| Prueba | Resultado esperado | OK |
|---|---|---|
| `--help` | Muestra la ayuda | |
| `--genkey` con almacén nuevo | Crea el almacén y guarda el alias | |
| `--genkey` con alias repetido | Error: el alias ya existe | |
| `--genkey` con contraseña de almacén mala | Error: contraseña incorrecta | |
| `--certreq` con almacén inexistente | Error: el almacén no existe | |
| `--certreq` con alias inexistente | Error: el alias no existe | |
| `--certreq` con contraseña de alias mala | Error: contraseña del alias incorrecta | |
| `--certreq` correcto | Crea `<alias>.csr` en PEM | |
