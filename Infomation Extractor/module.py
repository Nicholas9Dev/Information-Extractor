import argparse
import json
from datetime import datetime
import content
import pefile
import io
import re
from collections import Counter
import math






"""
Funções externas uteis para o funcionamento geral, funções de criações de arquivo e etc.




"""

"""

Estrutura basica de um analisador estatico, feito por um amador em programação.
Feito por @Nicholas9Dev no Github.

"""


class utilitary:
    
    def MakeTxtFile(self,  formato="No detected", entropy="No detected", lines="No requerid", archi="no detected", hash="no detected"):
            with open("relatorio.txt", "w") as f:
                f.write("Format : "+formato)
                f.write("\n")
                f.write("Entropy : "+ str(entropy))
                f.write("\n")
                f.write("Architecture : " + str(archi))
                f.write("\n")
                f.write("Hash SHA 256 : "+str(hash))
                f.write("\n")
                f.write("\n")
                f.write(str(lines))


    
    def MakeJsonFile(self, formato, entropy, hash="No detected", arch="No detected", lines="No detected"):
            with open("relatorio.json", "w") as f:
                
                data = {
        "Format": "Format : "+formato,
        "Entropy": "Entropy : "+str(entropy),
        "Architeture":"Architecture : " +arch,
        "Hash":"Hash SHA 256 : "+hash,
        "Strings":"\n\n{lines}",

}
                json.dump(data, f)

    
    def MensageError(self, menssage):
        with open("logs.txt") as f:
            f.write(f"{menssage} - {datetime.now()}\n")
    
    

    def ReceiveFlag(self):
        parser = argparse.ArgumentParser(description='Exemplo de passagem de argumentos')
        parser.add_argument('flag', type=str, help="Leia o Readme para saber mais!.", default="-txt")
        args = parser.parse_args()
        return args



def cicle():
    conteudo = content
    util = utilitary()
    arg = util.ReceiveFlag()

    if arg.flag == "txt":
        file = input("Selecione o nome do arquivo a ser Extraido:  ")
        bytes_s = conteudo.readfile(file)
        entropy = conteudo.calculate_entropy(bytes_s)
        lines  = conteudo.extract_strings_pe(bytes_s)
        formato = conteudo.formatpicker(bytes_s)
        hash = conteudo.found_sha256(file)
        arch = conteudo.get_architecture(file)
        util.MakeTxtFile(formato, entropy, lines, arch, hash)

    if arg.flag == "json":
        file = input("Selecione o nome do arquivo a ser Extraido:  ")
        bytes_s = conteudo.readfile(file)
        entropy = conteudo.calculate_entropy(bytes_s)
        lines  = conteudo.extract_strings_pe(bytes_s)
        formato = conteudo.formatpicker(bytes_s)
        hash = conteudo.found_sha256(file)
        arch = conteudo.get_architecture(file) 
        util.MakeJsonFile(formato, entropy, hash, arch, lines)

cicle()

    
"""
def IdentifyFlag(self, Flag):
        try:
            if Flag == "-json":
                self.MakeJsonFile()
                return 1
            if Flag == "-txt":
                self.MakeTxtFile()
                return 2
            
        except Exception as e:
                print("Flag Error")
                self.MensageError("Passe as flags corretamente babaca.") 
"""