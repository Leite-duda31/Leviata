# Leviatã
basicamente o código do meu projeto de reconhecimento, o Leviatã.

# 🔱 Leviatã 

[![Python Version](https://shields.io)](https://python.org)
[![Security Layer](https://shields.io)]()

O **Leviatã ** é um framework modular de reconhecimento tático e análise de segurança desenvolvido nativamente em Python. Projetado para operar com foco estrito em OpSec e evasão de heurísticas, a ferramenta combina auditoria de infraestrutura de rede em baixo nível com engenharia de fuzzing em aplicações web (Camadas 3, 4 e 7 do Modelo OSI).

---

## 🛠️ Arquitetura e Módulos Estruturais

A arquitetura do framework é dividida de forma isolada para garantir estabilidade, portabilidade e performance:

### 1. Motor de Infraestrutura (Raw SYN Scanner)
* **Sockets Brutos (`SOCK_RAW`):** Manipulação e montagem bit a bit dos cabeçalhos IP/TCP na pilha de rede.
* **Cálculo Nativo de Checksum:** Algoritmo próprio para validação de integridade dos pacotes gerados, evitando descartes pelo host de destino.
* **Simulação de OS Legítimo:** Utilização de IDs de IP incrementais e tamanhos de janela (*Window Size*) dinâmicos e legítimos.
* **Cortina de Fumaça (Decoys):** Dispersão de pacotes misturando múltiplos IPs gerados aleatoriamente ao IP do operador para confundir sistemas IDS/IPS.
* **Mapeamento Híbrido:** Detecção automática de redes internas locais para chaveamento automático de conexão, contornando bloqueios de gateways de borda.

### 2. Motor Web (Directory Fuzzer)
* Bypass de Heurísticas de WAF: Rotação dinâmica de *User-Agents* e injeção de cabeçalhos de geolocalização simulada (`X-Forwarded-For`, `X-Real-IP`)
* Calibragem por Assinatura: Varredura prévia contra comportamento *Catch-All* do servidor. O motor analisa o corpo e o número de linhas das respostas para filtrar falsos positivos com precisão.

### 3. Leviathan Scripting Engine (LSE)
* Auditoria Cirúrgica: Mecanismo interno focado no disparo de payloads assíncronos contra portas específicas previamente descobertas.
* Módulos Inline Atuais: Varredura estruturada de métodos HTTP expostos (OPTIONS) em portas Web e requisições brutos via UDP para detecção de versões de serviços (DNS BIND).

### 4. Gestão de OpSec e Utilitários
* Validação de Túneis: Mecanismo de contingência que testa a latência e integridade de proxies SOCKS/HTTP antes de expor o host real do operador.
* Anti-Rate Limiting: Controle estrito de timing baseado no nível de agressividade selecionado pelo operador (*Fantasma*, *Educado* ou *Agressivo*).

---

## 📊 Outputs e Relatórios

Toda a inteligência coletada durante o ciclo de execução da CLI interativa é sintetizada e tratada. O framework consolida:
* Portas abertas, serviços ativos e sistemas operacionais deduzidos (via análise passiva de TTL/Window).
* Vulnerabilidades identificadas pelo motor LSE.
* Diagnóstico de políticas de borda web (Cabeçalhos HTTP como HSTS, CSP, X-Frame-Options).
* Estrutura de diretórios mapeados.

Os dados são salvos em relatórios portáveis estruturados em formato JSON (`relatorio_leviata.json`) gerados com indexação automática anticolisão.

---

## 🧠 Aprendizados Técnicos

O desenvolvimento deste framework proporcionou uma compreensão aprofundada de:
1. Programação de rede em baixo nível e manipulação direta de sockets em ambientes POSIX/Windows.
2. Comportamento e respostas de firewalls corporativos e WAFs sob diferentes níveis de estresse e velocidade.
3. Engenharia de software aplicada à segurança defensiva e ofensiva.

além disso, eu construi essa ferramenta pois não tenho espaço o suficiente no meu computador para as ferramentas que preciso, sem ele virar uma bomba atomica... Então eu decidi construir minha propria ferramenta.

---
*Nota: Este projeto foi desenvolvido estritamente para fins educacionais, laboratórios controlados e pesquisa em engenharia de segurança.*
