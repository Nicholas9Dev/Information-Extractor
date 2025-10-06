import pefile
import io
import re
from collections import Counter
import math
import hashlib
import time
import datetime
import os


def readfile(path): #leitura do arquivo
    with open(path, "rb") as f:
        return f.read()

def formatpicker(input_):  #com os bytes passados pelo parametro, ele identifica o formato do arquivo e retorna o nome do formato.
    
    if isinstance(input_, (bytes, bytearray)):
        f = io.BytesIO(input_)
        close_after = True
    else:
        
        f = open(input_, "rb")
        close_after = True

    try:
        f.seek(0)
        magic4 = f.read(4) 

        if magic4[:2] == b'MZ': 

            f.seek(0x3C)
            e_lfanew = int.from_bytes(f.read(4), byteorder='little', signed=False)
            f.seek(e_lfanew)
            if f.read(4) == b'PE\x00\x00':
                return "Formato PE (Windows)"
            else:
                return "Arquivo com 'MZ' mas sem header PE válido"
        if magic4 == b'\x7fELF':
            return "Formato ELF (Linux)"
        if magic4 in [b'\xFE\xED\xFA\xCE', b'\xFE\xED\xFA\xCF',
                      b'\xCE\xFA\xED\xFE', b'\xCF\xFA\xED\xFE']:  
            return "Formato Mach-O (macOS)"
        if magic4[:4] == b'PK\x03\x04':
            return "Formato ZIP (ou JAR/APK)"
        return "Formato desconhecido"
    finally:
        if close_after:
            f.close()

def extract_strings_pe(data, min_len=5): #extrai as strings dos bytes passados.
    if isinstance(data, (str,)):
        with open(data, 'rb') as fh:
            data = fh.read()
    ascii_re = re.compile(b'[\\x20-\\x7e]{%d,}' % (min_len,))
    utf16le_re = re.compile((b'(?:[\\x20-\\x7e]\\x00){%d,}' % (min_len,)))
    ascii_matches = [s.decode('latin1') for s in ascii_re.findall(data)]
    utf16_matches = [s.decode('utf-16le') for s in utf16le_re.findall(data)]
    return ascii_matches + utf16_matches

def calculate_entropy(data): #calcular entropia.
    if isinstance(data, (str,)):
        with open(data, 'rb') as fh:
            data = fh.read()
    if not data:
        return 0.0
    byte_counts = Counter(data)
    total = len(data)
    entropy = -sum((count/total) * math.log2(count/total) for count in byte_counts.values() if count>0)
    return entropy

def MensageError(menssage):
    with open("logs.txt", "w") as f:
        f.write(f"{menssage} -\n")
    


def found_sha256(arquivo): #tenta detectar existencia e dps olha o tamanho, le em chunks de 4096 bytes cada e retorna o hash
    if not os.path.exists(arquivo):
        print(f"O arquivo {arquivo} não foi encontrado.")
        return None

    if os.path.getsize(arquivo) == 0:
        print(f"O arquivo {arquivo} está vazio.")
        return None

    try:
        with open(arquivo, 'rb') as f:
            sha256_hash = hashlib.sha256()

            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

            return sha256_hash.hexdigest()

    except Exception as e:
        print(f"Erro ao calcular SHA-256: {e}")
        return None

def get_architecture(file_path): #coleta a arch do arquivo 
    pe = pefile.PE(file_path)

    machine_type = pe.FILE_HEADER.Machine
    
    if machine_type == 0x14c:  # 32
        return "32-bit"
    elif machine_type == 0x8664:  # 64
        return "64-bit"
    else:
        return "Arquitetura desconhecida"




#"main"
def cicle(path):
    data = readfile(path)
    arch = get_architecture(path) 
    hash = found_sha256(data) 
    fmt = formatpicker(data)      
    strings = extract_strings_pe(data)
    entr = calculate_entropy(data)
    return  fmt, strings, entr, hash, arch



#depois separar os return





