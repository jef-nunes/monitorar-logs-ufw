import subprocess
from pathlib import Path
from pprint import pprint
from time import sleep
from typing import List

# A configuração padrão permite que o monitor
# seja atualizado a cada 1 segundo e analíse
# as 5 últimas linhas do arquivo de logs do firewall
class UFWLogMonitor:
    def __init__(self, logpath: str = '/var/log/ufw.log', n: int = 1, delay: float = 1) -> None:
        
        # Verificar se o caminho do log especificado existe
        if not Path(logpath).exists() or not Path(logpath).is_file():
            print(f"Erro - Caminho fornecido para os logs do UFW não encontrado: {logpath}")
            exit(1)

        # Definir o tempo de delay para o atualizador do monitor
        self.delay = delay

        # Comandos de shell para chamadas subprocess
        self.cmd_tail_ufw_log: List[str] = ['tail', '-n', str(n), str(logpath)]
        self.cmd_clear = ["clear"]
    
    # Executa o comando para limpar o terminal
    def limpar_terminal(self):
        subprocess.run(self.cmd_clear)

    # Inicia o loop da aplicação
    def loop(self):
        while True:
            parsing = subprocess.run(self.cmd_tail_ufw_log, capture_output=True, text=True)
            if parsing.returncode != 0:
                print("Erro ao executar o comando:", parsing.stderr)
                exit(1)            
            for log_line in parsing.stdout.splitlines():
                # Adicionar a linha à lista de logs analisados
                if log_line:
                    # Lógica para imprimir a linha formatada como um dicionário
                    #
                    # Dividir a linha nos espaços em branco
                    desc_list = log_line.split()
                    # Criar uma estrutura de dicionário
                    # com valores de padrão, usados
                    # para encontrar correspondências na linha dividida
                    pattern_map = {
                    #    "evento": "[UFW",
                        "in": "IN=",
                        "out": "OUT=",
                        "mac": "MAC=",
                        "source": "SRC=",
                        "destination": "DST=",
                        "length": "LEN=",
                        "tos": "TOS=",
                        "precedence": "PREC=",
                        "ttl": "TTL=",
                        "id": "ID=",
                        "dont_fragment": "DF",
                        "protocol": "PROTO="
                    }
                    # Dicionário de log para exibir no terminal
                    struct_log = {}

                    fmt_log_key_names = pattern_map.keys()
                    for key_name in fmt_log_key_names:
                        # Usar valores de espaço reservado como padrão para encontrar
                        ptrn = pattern_map[key_name]
                        # Para cada descrição como "PROTO=2"
                        # 
                        for desc in desc_list:
                            if desc.find(ptrn) != -1:
                                # "dont_fragment" deve ser exibido como um valor bool
                                # se encontrar uma correspondência, o bool será "verdadeiro".
                                # No final das iterações, se nenhuma correspondência for encontrada para "DF"
                                # será definido como "falso"
                                if ptrn == "DF":
                                    # "dont_fragment": True
                                    fmt_desc = True
                                else:
                                # Para outras descrições, use o formato a seguir
                                # que remove o rótulo e o caractere '=' se presente
                                    fmt_desc = desc.split('=')[1] if '=' in desc else desc
                                # Remover o padrão de espaço reservado no dicionário pattern_map
                                # e adicionar o valor fmt_desc
                                struct_log[f"{key_name}"] = fmt_desc
                                break
                    # Verificar se "dont_fragment" foi encontrado:
                    if pattern_map["dont_fragment"] == "DF":
                        # "dont_fragment": False
                        struct_log["dont_fragment"] = False
                    # Limpar terminal
                    self.limpar_terminal()
                    # Exibir o log formatado com pprint
                    print(" ")
                    pprint(struct_log)
            # Delay
            sleep(self.delay)


if __name__ == "__main__":
    monitor = UFWLogMonitor()
    monitor.loop()
