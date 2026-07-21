import socket
import sys
import urllib.parse
import urllib.request
import re
import ssl
import random
import time
import json

def construir_e_validar_pool_proxies():
    """Captura múltiplos proxies do operador, testa individualmente e monta a Whitelist ativa."""
    print("\n[📊] CONSTRUTOR DE POOL DE EVASÃO (MULTIPLEXER)")
    print("Injete os proxies (IP:PORTA). Pressione ENTER vazio para finalizar a lista.")
    
    pool_limpo = []
    contador = 1
    
    while True:
        p_input = input(f"  Digite o Proxy #{contador}: ").strip()
        if not p_input:
            break
            
        if not p_input.startswith(("http://", "https://")):
            proxy_url = f"http://{p_input}"
        else:
            proxy_url = p_input
            
        try:
            limpo = proxy_url.replace("http://", "").replace("https://", "")
            p_ip, p_porta = limpo.split(":")
            p_porta = int(p_porta)
            
            s_teste = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_teste.settimeout(2.5) 
            s_teste.connect((p_ip, p_porta))
            s_teste.close()
            
            print(f"    [+] \033[92mATIVO\033[0m: Proxy aceito e indexado no pool.")
            pool_limpo.append(proxy_url)
            contador += 1
        except Exception:
            print(f"    [!] \033[91mCORROMPIDO/TIMEOUT\033[0m: Proxy descartado da lista.")
            
    print(f"\n[+] Pool de Evasão consolidado: {len(pool_limpo)} proxies prontos para a rotação tática.")
    return pool_limpo if pool_limpo else None


def banner_grabber_cirurgico(ip, porta, agressividade, pool_proxies=None):
    # ─── ENGINE 1: JITTER (TEMPO MALUCO) ───
    agressividade = str(agressividade).strip()
    if agressividade == "1":
        time.sleep(random.uniform(0.5, 4.0))
    elif agressividade == "2":
        time.sleep(random.uniform(4.0, 10.0))
    elif agressividade == "3":
        time.sleep(random.uniform(10.0, 30.0)) 

    print(f"\n[*] CONSEGUINDO BANNER NA PORTA {porta}...")
    
    banner_bruto = ""
    porta_int = int(porta)
    
    # ─── ENGINE 2: USER-AGENT ROTATIVO ───
    lista_user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0"
    ]
    agent_sorteado = random.choice(lista_user_agents)
    
    proxy_da_rodada = random.choice(pool_proxies) if pool_proxies else None
    
    # Configura proxy para as requisições básicas, se houver
    if proxy_da_rodada:
        print(f"[#] Roteando tráfego via proxy: {proxy_da_rodada}")
        proxy_handler = urllib.request.ProxyHandler({'http': proxy_da_rodada, 'https': proxy_da_rodada})
        opener = urllib.request.build_opener(proxy_handler)
        urllib.request.install_opener(opener)
    else:
        contexto_ssl = ssl._create_unverified_context()
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=contexto_ssl))
        urllib.request.install_opener(opener)
    
    try:
        # CONEXÃO CAMADA 4 (TCP)
        soquete_base = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soquete_base.settimeout(4.5)
        
        if porta_int == 443:
            contexto = ssl._create_unverified_context()
            soquete = contexto.wrap_socket(soquete_base, server_hostname=ip)
        else:
            soquete = soquete_base
            
        soquete.connect((ip, porta_int))
        
        try:
            # Valida portas web legítimas para envio de requisição HTTP
            if porta_int in [80, 443, 8080] or porta_int == int(porta):
                requisicao_http = (
                    "HEAD / HTTP/1.1\r\n"
                    f"Host: {ip}\r\n"
                    f"User-Agent: {agent_sorteado}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode()
                soquete.send(requisicao_http)
            else:
                soquete.send(b"\r\n")
                
            resposta = soquete.recv(1024).decode('utf-8', errors='ignore').strip()
            
            match_server = re.search(r'(?i)^Server:\s*(.*)', resposta, re.M)
            if match_server:
                banner_bruto = match_server.group(1).strip()
            else:
                banner_bruto = resposta.split("\n")[0].strip() if resposta else ""
        except Exception:
            pass
        finally:
            soquete.close()
            
        if not banner_bruto or len(banner_bruto) < 3 or "HTTP/" in banner_bruto:
            banner_bruto = "Serviço Ativo (Banner oculto ou requer Handshake complexo)"
            
        print(f"\n--- [ LEVIATÃ: INTELIGÊNCIA DE DIAGNÓSTICO ATIVO ] ---")
        banner_limpo = banner_bruto.split("\n")[0].strip()
        termo_busca = re.sub(r"[^\w\s.-]", "", banner_limpo).strip()
        print(f"[+] Serviço Identificado na Porta {porta}: {termo_busca}")
        
        return {
            "banner_detectado": banner_bruto,
            "servico_limpo": termo_busca,
            "user_agent_utilizado": agent_sorteado,
            "proxy_utilizado": proxy_da_rodada if proxy_da_rodada else "Direto (Sem Proxy)",
            "status_alerta": "RECON_CONCLUIDO"
        }
        
    except Exception as e:
        return {"erro_conexao": f"Não foi possível conectar na porta {porta}: {e}"}


if __name__ == "__main__":
    try:
        print("--- [ LEVIATÃ - SCRIPT AUXILIAR: BANNER GRABBER EVASIVO ] ---")
        alvo_ip = input("Digite o IP do alvo: ").strip()
        alvo_porta = input("Digite a porta aberta: ").strip()
        alvo_agressividade = input("Escolha o nível de Jitter (1/2/3): ").strip()
        
        lista_proxies_validos = construir_e_validar_pool_proxies()
        
        resultado_diagnostico = banner_grabber_cirurgico(alvo_ip, alvo_porta, alvo_agressividade, lista_proxies_validos)
        
        print("\n[+] DIAGNÓSTICO FINAL DA CAMADA 7:")
        print(json.dumps(resultado_diagnostico, indent=4, ensure_ascii=False))
    except KeyboardInterrupt:
        print("\n[!] Script abortado pelo operador.")
