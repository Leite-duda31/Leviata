import json
import os
import random
import re
import ssl
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

def carregar_proxies(arquivo_proxies):
    if os.path.exists(arquivo_proxies):
        with open(arquivo_proxies, "r", encoding="utf-8") as f:
            
            proxies = [list_linha.strip() for list_linha in f if (linha := list_linha.strip()) and not linha.startswith("#")]
        print(f"[+] Pool de Evasão: {len(proxies)} proxies carregados com sucesso.")
        return proxies
    print("[!] Arquivo de proxies não encontrado. Operação em Modo Direto (Sem Evasão de IP).")
    return []

def requisicao_fuzzer_com_fallback(url_completa, user_agent, proxy_atual, timeout=4):
    """
    Executa o request tratando colisões de threads. 
    Se o proxy falhar (Timeout/Drop), ativa o Fallback Automático para Conexão Direta.
    """
    req = urllib.request.Request(url_completa, method="GET")
    req.add_header("User-Agent", user_agent)
    req.add_header("Accept", "*/*")
    req.add_header("Connection", "close")
    
    contexto_ssl = ssl._create_unverified_context()
    
    try:
        # TENTATIVA 1: Usando o Proxy do Pool
        if proxy_atual:
            if not proxy_atual.startswith(("http://", "https://")):
                proxy_url = f"http://{proxy_atual}"
            else:
                proxy_url = proxy_atual
            proxy_handler = urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url})
            opener = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler(context=contexto_ssl))
        else:
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=contexto_ssl))
            
        with opener.open(req, timeout=timeout) as resposta:
            return resposta.status, len(resposta.read())
            
    except urllib.request.HTTPError as e:
        return e.code, 0
        
    except Exception:
        # TENTATIVA 2: GATILHO DE FALLBACK (Se o proxy deu Drop, tenta Conexão Direta)
        if proxy_atual:
            try:
                opener_direto = urllib.request.build_opener(urllib.request.HTTPSHandler(context=contexto_ssl))
                with opener_direto.open(req, timeout=timeout) as resposta_direta:
                    return resposta_direta.status, len(resposta_direta.read())
            except urllib.request.HTTPError as e_direto:
                return e_direto.code, 0
            except Exception:
                return None, 0
        return None, 0

def trabalhador_agente_fantasma(rota, url_alvo, pool_proxies, lista_user_agents, agressividade, status_falso, tamanho_falso, achados):
    proxy_sorteado = random.choice(pool_proxies) if pool_proxies else None
    agent_atual = random.choice(lista_user_agents)
    
    url_completa = f"{url_alvo}/{rota}" if not url_alvo.endswith("/") else f"{url_alvo}{rota}"
    
    agressividade = str(agressividade).strip()
    if agressividade == "1":
        time.sleep(random.uniform(4.0, 12.0))
    elif agressividade == "2":
        time.sleep(random.uniform(0.4, 2.1))
        
    status, tamanho = requisicao_fuzzer_com_fallback(url_completa, agent_atual, proxy_sorteado)
    
    if status is None:
        print(f"  [!] \033[91mTIMEOUT/DROP\033[0m: Falha na rota /{rota}")
        return
        
    if tamanho == tamanho_falso and status == status_falso:
        return
        
   
    if status in [200, 201]:
        print(f"  [+] \033[92mFOUND (200)\033[0m: /{rota:<15} | Size: {tamanho}b")
        achados.append({"rota": rota, "status": status, "tamanho": tamanho})
        
    elif status in [301, 302, 307, 308]:
        print(f"  [➔] \033[36mREDIRECT ({status})\033[0m: /{rota:<15}")
        achados.append({"rota": rota, "status": status, "tamanho": tamanho})
        
    elif status in [401, 403]:
        print(f"  [🔒] \033[93mFORBIDDEN ({status})\033[0m: /{rota:<15} (Diretório Restrito)")
        achados.append({"rota": rota, "status": status, "tamanho": tamanho})
    
def iniciar_fuzzing_avancado(url_alvo, arquivo_wordlist, arquivo_proxies=None, agressividade="2"):
    print("\n" + "="*50)
    print("      LEVIATÃ EXTENSION: MULTI-THREADED COVERT FUZZER")
    print("="*50)
    
    pool_proxies = carregar_proxies(arquivo_proxies) if arquivo_proxies else []
    lista_user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0"
    ]
    
    print("[*] Mapeando comportamento de erros do servidor...")
    url_falsa = f"{url_alvo}/test_falso_positivo_{random.randint(1000,9999)}"
    
    
    status_falso, tamanho_falso = requisicao_fuzzer_com_fallback(url_falsa, random.choice(lista_user_agents), None)
    print(f"[*] Assinatura de erro padrão: Status {status_falso} | Size {tamanho_falso}b")

    if not os.path.exists(arquivo_wordlist):
        print(f"[!] Erro Crítico: Alvo exige arquivo de wordlist válido ({arquivo_wordlist})!")
        return
