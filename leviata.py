import json
import os
import random
import re
import socket
import struct
import sys
import ssl
import threading
import time
import urllib.parse
import urllib.request

# ==========================================
# MÓDULO 1: UTILITÁRIOS E ESTÁTICAS
# ==========================================
ip_id_lock = threading.Lock()
ip_id_global = random.randint(1000, 20000)

def statusserv():
    print("""       
# Básicos de serv (como ele está se sentindo)
 201 Created: (Feito!) 
 304 Not Modified: (Tá igualzinho)
 400 Bad Request: (Falou grego)
 401 Unauthorized: (Quem é você na fila do pão?)
 405 Method Not Allowed: (Não pode fazer isso aqui)
 429 Too Many Requests: (Segura a onda, emocionado!)
 500 Internal Server Error: (O código do cara quebrou)
 503 Service Unavailable: (Tô lotado ou em manutenção)""")


def calcular_checksum(msg):
    """Calcula o Checksum obrigatório para o cabeçalho TCP não ser descartado."""
    if len(msg) % 2 == 1:
        msg += b"\x00"
    s = 0
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i + 1] << 8)
        s = s + w
    s = (s >> 16) + (s & 0xFFFF)
    s = s + (s >> 16)
    s = ~s & 0xFFFF
    return s


def testar_e_configurar_proxy_transporte():
    """Solicita o proxy de transporte, valida a latência e configura o Fallback de OpSec."""
    print("\n[!] Configuração de Proxy de Transporte (Ex: 45.79.12.110:3128)")
    proxy_input = input("Digite o proxy (ou ENTER para rodar DIRETO): ").strip()
    
    if not proxy_input:
        print("[+] Modo de conexão: DIRETA (Seu IP real fará o tráfego)")
        return None

    if not proxy_input.startswith(("http://", "https://", "socks4://", "socks5://")):
        proxy_string = f"http://{proxy_input}"
    else:
        proxy_string = proxy_input

    print(f"[*] Testando integridade do túnel com o proxy {proxy_string}...")
    
    try:
        limpo = proxy_string.replace("http://", "").replace("https://", "").replace("socks5://", "").replace("socks4://", "")
        p_ip, p_porta = limpo.split(":")
        p_porta = int(p_porta)
    except Exception:
        print("[!] Erro de Sintaxe: Use o formato IP:PORTA")
        return None

    try:
        s_teste = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_teste.settimeout(4)
        s_teste.connect((p_ip, p_porta))
        s_teste.close()
        print(f"[+] PROXY DE TRANSPORTE RECEPTIVO! IP mascarado via: {proxy_string}")
        return {"string": proxy_string, "ip": p_ip, "porta": p_porta}
    except (socket.timeout, ConnectionRefusedError):
        print(f"\n[!] ALERTA DE TIMEOUT: O proxy {proxy_input} está inativo ou recusou a conexão!")
        decisao = input("[?] Deseja continuar a execução de forma DIRETA (Riscando seu IP real)? (s/n): ").strip().lower()
        if decisao == 's':
            print("[+] Contingência aceita: Conexão direta via host ativada.")
            return None
        else:
            print("[-] Operação cancelada pelo operador para preservar a OpSec.")
            return "ABORTAR"


# ==========================================
# MÓDULO 2: MOTOR INFRA - RAW SYN SCANNER
# ==========================================

def enviar_pacote_raw(ip_origem, ip_destino, porta_destino, flag_syn=True, flag_rst=False):
    """Monta manualmente os bytes das Camadas 3 e 4 do Modelo OSI com IP_ID incremental."""
    global ip_id_global
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except PermissionError:
        print("[!] ERRO DE PRIVILÉGIO: O Motor exige privilégios de Administrador/Sudo!")
        sys.exit(1)

    porta_origem = random.randint(2000, 65000)
    seq_num = random.randint(100000, 900000)
    ack_num = 0

    with ip_id_lock:
        ip_id_global = (ip_id_global + 1) & 0xFFFF  
        ip_id_atual = ip_id_global

    ip_ihl_ver = (4 << 4) + 5
    ip_tos = 0
    ip_tot_len = 0
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(ip_origem)
    ip_daddr = socket.inet_aton(ip_destino)

    cabecalho_ip = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ihl_ver, ip_tos, ip_tot_len, ip_id_atual, ip_frag_off,
        ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr
    )

    tcp_doff_res = (5 << 4) + 0
    tcp_flags = (1 if flag_rst else 0) << 2 | (1 if flag_syn else 0) << 1
    
    janelas_legitimas = [1024, 2048, 4096, 8192, 14600, 65535]
    tamanho_janela_dinamico = random.choice(janelas_legitimas) if not flag_rst else 0
    tcp_window = socket.htons(tamanho_janela_dinamico)
    
    tcp_check = 0
    tcp_urg_ptr = 0

    cabecalho_tcp_provisorio = struct.pack(
        "!HHLLBBHHH",
        porta_origem, porta_destino, seq_num, ack_num,
        tcp_doff_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr
    )

    pseudo_cabecalho = struct.pack(
        "!4s4sBBH",
        ip_saddr, ip_daddr, 0, ip_proto, len(cabecalho_tcp_provisorio)
    )
    tcp_check = calcular_checksum(pseudo_cabecalho + cabecalho_tcp_provisorio)

    cabecalho_tcp_final = struct.pack(
        "!HHLLBBHHH",
        porta_origem, porta_destino, seq_num, ack_num,
        tcp_doff_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr
    )

    s.sendto(cabecalho_ip + cabecalho_tcp_final, (ip_destino, 0))
    s.close()
    return porta_origem


def escutar_syn_ack(ip_alvo, porta_alvo, porta_local):
    """Escuta na placa de rede se o alvo respondeu com SYN-ACK (Porta Aberta)."""
    s_escuta = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s_escuta.settimeout(1.2)

    tempo_inicio = time.time()
    while time.time() - tempo_inicio < 1.2:
        try:
            dados, _ = s_escuta.recvfrom(65565)
            ttl_passivo = dados[8] 
            ip_header_len = (dados[0] & 0x0F) * 4
            ip_origem = socket.inet_ntoa(dados[12:16])
            
            if ip_origem != ip_alvo:
                continue

            tcp_dados = dados[ip_header_len : ip_header_len + 20]
            tcph = struct.unpack("!HHLLBBHHH", tcp_dados)

            if tcph[0] == porta_alvo and tcph[1] == porta_local and tcph[5] == 18:
                window_passivo = tcph[7]
                s_escuta.close()
                return True, ttl_passivo, window_passivo
        except socket.timeout:
            break
        except Exception:
            pass

    s_escuta.close()
    return False, None, None


def motor_furtivo_avancado(meu_ip, ip_alvo, porta, agressividade, resultados):
    """Detecta automaticamente se o alvo é local ou externo e executa a varredura híbrida com alertas de portas filtradas."""
    agressividade = str(agressividade).strip()
    
    if agressividade == "1":
        time.sleep(random.uniform(2.0, 15.0))
    elif agressividade == "2":
        time.sleep(random.uniform(0.2, 3.0))
    elif agressividade == "3":
        time.sleep(random.uniform(0.01, 0.2))

    # --- ENGENHARIA DE REDE LOCAL (BYPASS DE FIREWALL DE GATEWAY) ---
    eh_ip_local = ip_alvo.startswith(("192.168.", "10.", "172.16.", "127."))
    
    if eh_ip_local:
        try:
            s_local = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_local.settimeout(1.5) # Timeout calibrado para capturar o gelo do roteador
            resultado_conexao = s_local.connect_ex((ip_alvo, porta))
            
            if resultado_conexao == 0:
                print(f"[+] Porta {porta}: ABERTA (Mapeamento Local Direto)")
                servico = f"Serviço Ativo: {porta}"
                if porta in[80,443,8080]: 
                    servico = "Apache/Nginx (Web)"
                elif porta == 22: servico = "OpenSSH"
                elif porta == 21: servico = "Pure-FTPd"
                elif porta == 23: servico = "Telnet"
                elif porta == 445: servico = "SMB (Windows)"
                elif porta == 3306: servico = "MySQL"
                elif porta == 3389: servico = "RDP Windows"
                
                resultados[porta] = {"servico": servico, "os": "Localhost / Gateway Interno", "status": "Aberta"}
            else:
                # CORREÇÃO: Avisa o operador se o roteador barrou, dropou ou recusou a porta local
                print(f"[-] Porta {porta}: \033[93mFILTERED / CLOSED\033[0m (Código: {resultado_conexao})")
                
            s_local.close()
            return
        except Exception:
            return

    # --- MOTOR INTERNET ORIGINAL (RAW SYN + DECOYS) ---
    decoys = [
        f"{random.randint(1,223)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        for _ in range(10)
    ]

    posicao_real = random.randint(0, 10)
    decoys.insert(posicao_real, meu_ip)

    porta_local_escuta = None
    for ip_origem_falso in decoys:
        is_real = ip_origem_falso == meu_ip
        p_local = enviar_pacote_raw(ip_origem_falso, ip_alvo, porta, flag_syn=True, flag_rst=False)
        if is_real:
            porta_local_escuta = p_local
        time.sleep(random.uniform(0.02, 0.1))

    porta_aberta, ttl_detectado, window_detectado = escutar_syn_ack(ip_alvo, porta, porta_local_escuta)

    if porta_aberta:
        print(f"[+] Porta {porta}: ABERTA | TTL: {ttl_detectado} | Window Size: {window_detectado}")
    
    # 1. Dedução do Sistema Operacional (OS)
        so_deduzido = "Desconhecido"
        if ttl_detectado:
            if ttl_detectado <= 64: so_deduzido = "Linux / Unix / macOS"
            elif ttl_detectado <= 128: so_deduzido = "Windows (Moderno)"
            elif ttl_detectado <= 255: so_deduzido = "Dispositivo de Rede (Roteador)"

        if window_detectado and so_deduzido == "Desconhecido":
            if window_detectado in[5840, 29200]: so_deduzido = "Linux / Unix"
            elif window_detectado in[16384, 65535, 8192]: so_deduzido = "Windows"
            
    # 2. Mapeamento de Serviços usando Dicionário (Mais rápido e limpo)
        mapeamento_portas = {
            21: "Pure-FTPd",
            22: "OpenSSH",
            23: "Telnet",
            53: "Resolvedor DNS",
            80: "Apache/Nginx (Web)",
            443: "Apache/Nginx (Web)",
            445: "SMB (Windows)",
            3306: "MySQL",
            3389: "RDP Windows",
            3478: "VoIP / Chamadas de Vídeo",
            8080: "Apache/Nginx (Web)"
        }   

    # Busca a porta no dicionário. Se não achar, define como "Serviço Ativo"
        servico = mapeamento_portas.get(porta, "Serviço Ativo")

    # Se a porta não está mapeada nas conhecidas (incluindo as de e-mail do seu código antigo)
        portas_conhecidas = list(mapeamento_portas.keys()) + [25, 143, 547, 587]
        if porta not in portas_conhecidas:
            print(f"[+] A porta encontrada foi: {porta}.")

    # 3. Salvando resultados e enviando RST (Fechar a conexão aberta pelo SYN-ACK)
        resultados[porta] = {"servico": servico, "os": so_deduzido, "status": "Aberta"}
        enviar_pacote_raw(meu_ip, ip_alvo, porta, flag_syn=False, flag_rst=True)

    else:
    # Se bater na internet e der timeout no SYN-ACK, joga o log de filtrada
        print(f"[-] Porta {porta}: FILTERED (Sem resposta SYN-ACK e nem RST, caba dropou apenas)")



# ==========================================
# MÓDULO 3: MOTOR WEB - DIRECTORY FUZZER (9/10)
# ==========================================

def testar_diretorio_com_evasao_l7(url_base, diretorio, agressividade, assinatura_falsa, achados, pool_proxies=None):
    """
    Fuzzer Web Avançado com Rotação de Proxies e Ofuscação Estrita de Cabeçalhos HTTP 
    para quebrar heurísticas de WAF. Blindado contra vazamento de variáveis em exceções.
    """
    agressividade = str(agressividade).strip()
    
    # Controle rígido de timing (Anti-Rate Limiting)
    if agressividade == "1":
        time.sleep(random.uniform(4.0, 12.0))
    elif agressividade == "2":
        time.sleep(random.uniform(0.5, 2.5))

    url_completa = f"{url_base}/{diretorio}" if not url_base.endswith("/") else f"{url_base}{diretorio}"

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    ]
    
    # Cabeçalhos realistas combinados com técnicas de bypass de IP na Camada 7
    headers_completos = {
        "User-Agent": random.choice(user_agents),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
        "Cache-Control": "max-age=0",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "X-Forwarded-For": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
        "X-Real-IP": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    }

    # Inicialização estrita de contingência (Evita NameError em blocos except)
    proxy_escolhido = "Direto"
    handler_proxy = urllib.request.ProxyHandler({})
    
    if pool_proxies:
        proxy_escolhido = random.choice(pool_proxies)
        handler_proxy = urllib.request.ProxyHandler({
            "http": proxy_escolhido,
            "https": proxy_escolhido
        })
    
    contexto_ssl = ssl._create_unverified_context()
    handler_ssl = urllib.request.HTTPSHandler(context=contexto_ssl)
    
    opener = urllib.request.build_opener(handler_proxy, handler_ssl)
    req = urllib.request.Request(url_completa, headers=headers_completos)
    
    try:
        with opener.open(req, timeout=5) as resposta:
            status = resposta.status
            conteudo = resposta.read()
            
            # Converte para string ignorando erros para validar estrutura/linhas
            texto_real = conteudo.decode('utf-8', errors='ignore')
            linhas_reais = len(texto_real.splitlines())
            tamanho_real = len(conteudo)

            # Evita colisões se a estrutura for idêntica ao erro padrão mapeado
            if linhas_reais == assinatura_falsa:
                return

            if status == 200:
                print(f"  [+] \033[92mFOUND\033[0m: {url_completa} (Status: {status} | Size: {tamanho_real}b) -> Via Proxy: {proxy_escolhido}")
                achados.append({"url": url_completa, "status": status, "tipo": "Acessivel"})
                
    except urllib.request.HTTPError as e:
        if e.fp:
            corpo_erro = e.read().decode('utf-8', errors='ignore')
            linhas_erro = len(corpo_erro.splitlines())
            tamanho_erro = len(corpo_erro)
        else:
            linhas_erro = 0
            tamanho_erro = 0
        
        # Ignora se for a página padrão de erro 404 do alvo ou Catch-All baseado em linhas
        if e.code == 404 or linhas_erro == assinatura_falsa:
            return
            
        # Captura redirecionamentos e restrições críticas de Camada 7
        if e.code in[301,302, 303, 307,307, 403,401]:
            print(f"  [+] \033[93mRESTRICTED/REDIRECT\033[0m: {url_completa} (Status: {e.code} | Size: {tamanho_erro}b) -> Via Proxy: {proxy_escolhido}")
            achados.append({"url": url_completa, "status": e.code, "tipo": "Restrito"})
        elif e.code == 429:
            print(f"  [!] \033[91mRATE LIMIT\033[0m: Alvo barrou por velocidade (Status: {e.code}) -> Via Proxy: {proxy_escolhido}")
    except Exception:
        pass


def motor_diretorios_web(url_base, agressividade, pool_proxies=None):
    """Gerencia o fuzzer de caminhos ocultos contra Catch-All com assinatura ofuscada."""
    print(f"\n--- [ LEVIATÃ: WEB DIRECTORY FUZZER ] ---")
    print(f"[*] Analisando comportamento de falsos positivos do servidor alvo...")

    contexto_ssl = ssl._create_unverified_context()
    # Simula uma chamada de script dinâmico comum de CMS
    url_falsa = f"{url_base}/wp-content/themes/twentytwenty/assets/js/main_{random.randint(100,999)}.js"
    assinatura_falsa = -1
    
    try:
        req_falsa = urllib.request.Request(url_falsa, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req_falsa, timeout=3, context=contexto_ssl) as resp_falsa:
            conteudo_falso = resp_falsa.read().decode('utf-8', errors='ignore')
            assinatura_falsa = len(conteudo_falso.splitlines())
            print(f"[*] Detectado comportamento Catch-All. Assinatura padrão: {assinatura_falsa} linhas de HTML.")
    except urllib.request.HTTPError as e:
        if e.fp:
            conteudo_erro = e.read().decode('utf-8', errors='ignore')
            assinatura_falsa = len(conteudo_erro.splitlines())
        else:
            assinatura_falsa = 0
        print(f"[+] Servidor responde {e.code} normalmente. Assinatura de erro fixada em: {assinatura_falsa} linhas.")
    except Exception as e:
        print(f"[!] Erro ao testar Catch-All: {e}")
        
    wordlist = [
        "admin", "administrator", "login", "wp-admin", "painel", "dashboard",
        "phpmyadmin", "cpanel", "webmail", "signin", "auth", "user/login",
        "api/auth", "manage", "manager", "controlpanel", "adm", "secure",
        "checkpoint", "private", ".env", "config.php", "config.bak", "config.json",
        "configuration.php", "setting.php", "settings.py", "database.yml",
        "wp-config.php", ".git", ".git/config", ".svn", ".htaccess",
        ".bash_history", ".ssh/id_rsa", "boot.ini", "web.config",
        "docker-compose.yml", "package.json", "composer.json", "backup",
        "backups", "backup.zip", "backup.tar.gz", "backup.sql", "db",
        "database.sql", "dump.sql", "db.sql", "site.zip", "main.zip", "old",
        "vello", "test", "demo", "staging", "prod", "patch", "archive",
        "archives", "api", "v1", "v2", "v3", "graphql", "swagger",
        "swagger-ui.html", "api-docs", "docs", "documentation", "rest", "ws",
        "metrics", "actuator", "actuator/health", "status", "health",
        "server-status", "rpc", "xmlrpc.php", "uploads", "images", "img",
        "assets", "css", "js", "static", "files", "documents", "downloads",
        "media", "public", "shared", "storage", "temp", "tmp", "attachments",
        "import", "export", "robots.txt", "var"
    ]
    random.shuffle(wordlist)
    print(f"[*] Wordlist tática embaralhada: {len(wordlist)} caminhos na fila.")
    print("[*] Iniciando Fuzzing...\n")
    
    diretorios_achados = []
    for pasta in wordlist:
        testar_diretorio_com_evasao_l7(url_base, pasta, agressividade, assinatura_falsa, diretorios_achados, pool_proxies)
        
    print("[*] Varredura de diretórios finalizada.")
    return diretorios_achados

# ========================================================
# MÓDULO 4: LSE (LEVIATHAN SCRIPTING ENGINE) - SCRIPTS INLINE
# ========================================================

def script_lse_http_options(ip, porta, agent_sorteado):
    """LSE_HTTP_01: Varre métodos permitidos para achar verbos perigosos (PUT/DELETE/TRACE)."""
    try:
        requisicao = (
            "OPTIONS / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"User-Agent: {agent_sorteado}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.5)
            s.connect((ip, porta))
            s.sendall(requisicao)
            resposta = s.recv(2048).decode('utf-8', errors='ignore')
            
            match_allow = re.search(r'(?i)^Allow:\s*(.*)', resposta, re.M)
            if match_allow:
                metodos = match_allow.group(1).strip()
                alerta = "INFORMACIONAL"
                if "PUT" in metodos or "DELETE" in metodos or "TRACE" in metodos:
                    alerta = "ALTO"
                return {"id": "LSE_HTTP_01", "vuln": "Métodos HTTP Expostos", "detalhe": metodos, "alerta": alerta}
    except Exception:
        pass
    return None

def script_lse_dns_version(ip, porta=53):
    """LSE_DNS_01: Envia um payload bruto UDP perguntando a versão exata do BIND/DNS."""
    payload_dns = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2.5)
            s.sendto(payload_dns, (ip, porta))
            resposta, _ = s.recvfrom(512)
            if b"bind" in resposta.lower() or len(resposta) > 12:
                return {"id": "LSE_DNS_01", "vuln": "Vazamento de Versão DNS", "detalhe": "Servidor respondeu ao payload version.bind", "alerta": "MEDIO"}
    except Exception:
        pass
    return None

# ========================================================
# MÓDULO 5: CLI INTERATIVA & OUVINTE SECRETO RESTRUTURADO
# ========================================================

def ouvinte_secreto():
    while True:
        frase = input("\nLEVIATÃ > ").strip()
        
        if frase.upper() == "SCANNER":
            entrada_usuario = input("Digite a URL ou IP do alvo (ex: 127.0.0.1 ou exemplo.com): ").strip()
            padrao_ip = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
            
            if re.match(padrao_ip, entrada_usuario):
                ip = entrada_usuario
                url = f"http://{ip}"
                print(f"[+] Alvo identificado como IP direto: {ip}")
            else:
                url_usuario = entrada_usuario
                if not url_usuario.startswith(("http://", "https://")):
                    url = f"https://{url_usuario}"
                else:
                    url = url_usuario
                    
                dominio = url.replace("http://", "").replace("https://", "").split("/")[0]
                
                try:
                    ip = socket.gethostbyname(dominio)
                    print(f"[+] Domínio resolvido! O IP do site é: {ip}")
                except Exception as e:
                    print(f"[!] Não foi possível obter o IP via DNS: {e}")
                    continue

            dados_scan = {
                "alvo_url": url,
                "ip": ip,
                "sistema_operacional": "Desconhecido",
                "politicas_seguranca_web": {},
                "portas_abertas": {},
                "vulnerabilidades_lse": [],
                "diretorios_vulneraveis": []
            }
            
            print("\nNíveis de Agressividade (Furtividade):")
            print(" [1] Fantasma (Delay alto por porta/request - Altamente Furtivo)")
            print(" [2] Educado  (Delay moderado - Recomendado para Labs)")
            print(" [3] Agressivo (Sem delay - Rápido / Barulhento)")
            agressividade = input("Escolha o nível (1/2/3): ").strip()
            if agressividade not in ["1", "2", "3"]:
                agressividade = "2"
                
            print("\n[!] Digite as portas separadas por vírgula (ex: 80, 443, 21) ou digite 'comuns'")
            input_portas = input("Portas para testar: ").strip().lower()
            
            if input_portas == "comuns":
                portas_para_testar = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9000, 27017]
            else:
                portas_para_testar = [int(p.strip()) for p in input_portas.split(",") if p.strip().isdigit()]
                
            print(f"\n[*] ENVIANDO REQUISIÇÃO PARA: {url}")
            
            try:
                s_ip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s_ip.connect(("8.8.8.8", 80))
                meu_ip = s_ip.getsockname()[0]
                s_ip.close()
            except Exception:
                meu_ip = "127.0.0.1"
                
            proxy_infra = testar_e_configurar_proxy_transporte()
            if proxy_infra == "ABORTAR":
                continue

            print("\n[*] ESCANEANDO PORTAS COM SEGURANÇA MÁXIMA...")
            random.shuffle(portas_para_testar)
            resultados_finais = {}
            threads = []
            
            # User-Agent randômico para as chamadas do LSE
            lista_ua = ["Mozilla/5.0 Chrome/122.0.0.0", "Mozilla/5.0 Safari/17.3", "Mozilla/5.0 Firefox/119.0"]
            ua_sorteado = random.choice(lista_ua)
            
            for porta in portas_para_testar:
                if proxy_infra:
                    try:
                        s_proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s_proxy.settimeout(3)
                        s_proxy.connect((proxy_infra["ip"], proxy_infra["porta"]))
                        
                        comando = f"CONNECT {ip}:{porta} HTTP/1.1\r\n\r\n"
                        s_proxy.sendall(comando.encode())
                        resposta = s_proxy.recv(1024).decode(errors="ignore")
                        
                        if "200 Connection established" in resposta or "200 OK" in resposta:
                            servico = "Serviço Ativo"
                            if porta in[80,443,8080]: servico = "Apache/Nginx (Web)"
                            elif porta == 22: servico = "OpenSSH"
                            elif porta == 21: servico = "Pure-FTPd"
                            elif porta == 445: servico = "SMB (Windows)"
                                
                            print(f"[+] Porta {porta}: ABERTA (Via Proxy)")
                            resultados_finais[porta] = {"servico": servico, "os": "Tunelado por Proxy", "status": "Aberta"}
                        s_proxy.close()
                    except Exception:
                        pass
                else:
                    if agressividade == "1":
                        motor_furtivo_avancado(meu_ip, ip, porta, agressividade, resultados_finais)
                    else:
                        t = threading.Thread(
                            target=motor_furtivo_avancado,
                            args=(meu_ip, ip, porta, agressividade, resultados_finais),
                        )
                        threads.append(t)
                        t.start()
                        time.sleep(random.uniform(0.04, 0.15))
                    
            if not proxy_infra and agressividade != "1":
                for t in threads:
                    t.join()

            print("[*] Varredura de portas finalizada.")
            dados_scan["portas_abertas"] = resultados_finais
            
            if resultados_finais:
                primeira_porta = list(resultados_finais.keys())[0]
                so_provavel = resultados_finais[primeira_porta]["os"]
                dados_scan["sistema_operacional"] = so_provavel
            else:
                so_provavel = "Desconhecido (Nenhuma porta respondeu)"
                dados_scan["sistema_operacional"] = so_provavel
                
            print(f"[=>] Sistema Operacional Provável: {so_provavel}\n")
            
            # --- DISPARADOR ATIVO DO MOTOR DE SCRIPTS LSE (A MOSCA) ---
            print("[*] LSE: Inicializando auditoria cirúrgica de scripts stealth...")
            vulnerabilidades_descobertas = []
            for p_aberta, info_p in resultados_finais.items():
                if info_p.get("status") == "Aberta":
                    if p_aberta in[80, 443, 8080]:
                        res_lse = script_lse_http_options(ip, p_aberta, ua_sorteado)
                        if res_lse: vulnerabilidades_descobertas.append(res_lse)
                    elif p_aberta == 53:
                        res_lse = script_lse_dns_version(ip, p_aberta)
                        if res_lse: vulnerabilidades_descobertas.append(res_lse)
            
            dados_scan["vulnerabilidades_lse"] = vulnerabilidades_descobertas
            print("[*] LSE: Auditoria concluída.")
            
            url_web = url if url.startswith(("http://", "https://")) else "http://" + url
            try:
                req = urllib.request.Request(url_web, headers={"User-Agent": ua_sorteado})
                resposta = urllib.request.urlopen(req, timeout=5)
                codigo_status = (resposta.status, resposta.reason)
                cabecalhos = resposta.info()
                
                print("[+] CABEÇALHOS CAPTURADOS:")
                politicas_verificacao = {
                    "Strict-Transport-Security": "HSTS (Forçar HTTPS)",
                    "X-Frame-Options": "Proteção contra Iframe/Clickjacking",
                    "X-Content-Type-Options": "Proteção contra XSS Sniffing",
                    "Content-Security-Policy": "CSP (Controle de Scripts)",
                }
                for header, descricao in politicas_verificacao.items():
                    valor = cabecalhos.get(header)
                    if valor:
                        print(f"  [ PROTEGIDO ] {descricao}: {valor}")
                        dados_scan["politicas_seguranca_web"][descricao] = {"status": "Configurado", "valor": valor}
                    else:
                        print(f"  [ VULNERÁVEL ] {descricao} AUSENTE!")
                        dados_scan["politicas_seguranca_web"][descricao] = {"status": "AUSENTE", "valor": None}
                print(f"-> Status do servidor: {codigo_status}")
            except Exception as e:
                print(f"[!] ERRO DE CONEXÃO HTTP: {e}")
                
            opcao = input("\n[?] Deseja rodar o Fuzzer de diretórios neste alvo? (s/n): ").strip().lower()
            if opcao == "s":
                pool_usuario = [proxy_infra["string"]] if proxy_infra else None
                diretorios_reais = motor_diretorios_web(url_web, agressividade, pool_usuario)
                dados_scan["diretorios_vulneraveis"] = diretorios_reais
            else:
                print("[*] Fuzzing de diretórios pulado pelo operador.")
                
            # ========================================================
            # PAINEL RESTRUTURADO: CONSOLIDADO TÁTICO FINAL DO LEVIATÃ
            # ========================================================
            print("\n" + "="*55)
            print("       LEVIATÃ: RESUMO EXECUTIVO DE INTELIGÊNCIA")
            print("="*55)
            print(f"[•] ALVO EXECUTADO : {entrada_usuario}")
            print(f"[•] IP DO ALVO     : {ip}")
            print(f"[•] AGRESSIVIDADE  : Nível {agressividade}")
            print(f"[•] S.O. PROVÁVEL  : {so_provavel}")
            print("-" * 55)
            print(" PORTA   | STATUS             | SERVIÇO / ASSINATURA")
            print("-" * 55)
            
            if not resultados_finais:
                print("  [!] Nenhuma porta aberta foi detectada neste host.")
            else:
                for porta_id, info_porta in resultados_finais.items():
                    p_status = info_porta.get("status", "Aberta")
                    p_servico = info_porta.get("servico", "Serviço Ativo")
                    print(f"  {porta_id:<6} | {p_status:<18} | {p_servico}")
                    
            print("-" * 55)
            print("[!] VULNERABILIDADES INTERNAS DETECTADAS (LSE):")
            if not vulnerabilidades_descobertas:
                print("  [+] Nenhum script LSE disparou alertas críticos nas portas abertas.")
            else:
                for v in vulnerabilidades_descobertas:
                    v_alerta = v["alerta"]
                    v_cor = f"\033[91m{v_alerta}\033[0m" if v_alerta == "ALTO" else f"\033[93m{v_alerta}\033[0m"
                    print(f"  • [{v_cor}] {v['id']} - {v['vuln']}: {v['detalhe']}")
                    
            print("-" * 55)
            print("[+] POLÍTICAS DE BORDA WEB (CABEÇALHOS CAPTURADOS):")
            if not dados_scan["politicas_seguranca_web"]:
                print("  [!] Nenhuma resposta HTTP capturada para este host.")
            else:
                for desc, status_h in dados_scan["politicas_seguranca_web"].items():
                    v_status = status_h["status"]
                    v_print = f"\033[92m{v_status}\033[0m" if v_status == "Configurado" else f"\033[91m{v_status}\033[0m"
                    print(f"  • {desc:<35} -> {v_print}")
                    
            if opcao == "s":
                print(f"[•] DIRETÓRIOS IDENTIFICADOS: {len(dados_scan['diretorios_vulneraveis'])} encontrados.")
            print("="*55 + "\n")
                
            print("[*] Exportando dados consolidados do Leviatã...")
            base_nome = "relatorio_leviata"
            extensao = ".json"
            contador = 1
            nome_arquivo = f"{base_nome}{extensao}"
            
            while os.path.exists(nome_arquivo):
                nome_arquivo = f"{base_nome}_{contador}{extensao}"
                contador += 1
                
            try:
                with open(nome_arquivo, "w", encoding="utf-8") as f_json:
                    json.dump(dados_scan, f_json, indent=4, ensure_ascii=False)
                print(f"[+] SUCESSO: Dados estruturados salvos em '{nome_arquivo}'!")
            except Exception as e:
                print(f"[!] Erro ao salvar arquivo JSON: {e}")
                
        elif frase.upper() == "MAN STATUS SERV":
            statusserv()
            
        elif frase.upper() == "ENCERRAR":
            print("\n[-] Finalizando o Leviatã...")
            break
        else:
            print("mano, vai pegar um café, vc tá dormindo?? vc consegue, mas de olhos fechados ainda não!!")
        if frase.upper() == ";-;":
            print("você sabe que leva tempo né? e que se for desistir no meio, é melhor nem começar, por isso, sempre que se sentir pra baixo, lembre-se, elon musk sempre se fodia e nem por isso ele desistiu, olha onde o cara tá hoje!! ")
            
if __name__ == "__main__":
    try:
        # Inicializa o console com a identidade visual da corporação
        print("\033[94m" + "="*55 + "\033[0m")
        print(" M O R N I N G S T A R  |  L E V I A T Ã")
        print(" [ Framework de Reconhecimento Furtivo ]")
        print("\033[94m" + "="*55 + "\033[0m")
        
        # Dá o start no loop infinito da CLI interativa
        ouvinte_secreto()
        
    except KeyboardInterrupt:
        print("\n\n[-] Operação abortada via teclado pelo operador. Encerrando host.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Falha crítica no Kernel do script: {e}")
        sys.exit(1)
