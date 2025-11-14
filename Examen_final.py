from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64

def fnv1_hash(mensaje):
    offset = 2166136261
    prime = 16777619
    h = offset
    for c in mensaje:
        h = (h * prime) ^ ord(c)
        h &= 0xffffffff
    return h

def rle_comprimir(mensaje):
    if mensaje == "":
        return ""
    comp = ""
    cont = 1
    for i in range(1, len(mensaje)):
        if mensaje[i] == mensaje[i-1]:
            cont += 1
        else:
            comp += mensaje[i-1] + str(cont)
            cont = 1
    comp += mensaje[-1] + str(cont)
    return comp

def rle_descomprimir(comp):
    res = ""
    i = 0
    while i < len(comp):
        letra = comp[i]
        i += 1
        num = ""
        while i < len(comp) and comp[i].isdigit():
            num += comp[i]
            i += 1
        res += letra * int(num)
    return res

def generar_claves():
    privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    publica = privada.public_key()
    return publica, privada

def firmar(hash_val, clave_priv):
    hash_bytes = hash_val.to_bytes(4, "big")
    firma = clave_priv.sign(
        hash_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return firma

def verificar(firma, hash_val, clave_pub):
    try:
        hash_bytes = hash_val.to_bytes(4, "big")
        clave_pub.verify(
            firma,
            hash_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except:
        return False

mensaje = ""
hash_actual = None
comprimido = ""
firma = None
clave_publica = None
clave_privada = None
paquete = None

while True:
    print("""
1. Ingresar mensaje
2. Calcular hash FNV-1
3. Comprimir mensaje
4. Firmar hash con clave privada RSA
5. Simular envío
6. Descomprimir y verificar firma
7. Mostrar si el mensaje es auténtico o alterado
8. Salir
""")
    
    op = input("Opción: ")

    match op:
        case "1":
            mensaje = input("Mensaje: ")

        case "2":
            if mensaje == "":
                print("No hay mensaje.")
            else:
                hash_actual = fnv1_hash(mensaje)
                print("Hash:", hash_actual)

        case "3":
            if mensaje == "":
                print("No hay mensaje.")
            else:
                comprimido = rle_comprimir(mensaje)
                print("Comprimido:", comprimido)

        case "4":
            if hash_actual is None:
                print("Falta hash.")
            else:
                clave_publica, clave_privada = generar_claves()
                firma = firmar(hash_actual, clave_privada)
                print("Firma generada (Base64):", base64.b64encode(firma).decode())

        case "5":
            if comprimido == "" or firma is None:
                print("Faltan datos.")
            else:
                paquete = {
                    "mensaje": comprimido,
                    "firma": firma,
                    "clave_publica": clave_publica
                }
                print("Envío simulado.")

        case "6":
            if paquete is None:
                print("Nada recibido.")
            else:
                recib = paquete["mensaje"]
                f = paquete["firma"]
                kpub = paquete["clave_publica"]

                descomp = rle_descomprimir(recib)
                nuevo_hash = fnv1_hash(descomp)
                valido = verificar(f, nuevo_hash, kpub)

                print("Mensaje descomprimido:", descomp)
                print("Hash recalculado:", nuevo_hash)
                print("Firma válida:", valido)
                ultimo_valido = valido

        case "7":
            try:
                if ultimo_valido:
                    print("Mensaje auténtico.")
                else:
                    print("Mensaje alterado.")
            except:
                print("Aún no se ha verificado nada.")

        case "8":
            break

        case _:
            print("Opción inválida.")
