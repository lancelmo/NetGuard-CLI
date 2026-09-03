# NetGuard Cyber Defense Network Engine v1.2 → Web Engine v2.0 (Projeto 2)

Este projeto é uma ferramenta de auditoria de segurança e monitoramento de ativos de rede local, desenvolvida como projeto prático para a disciplina de **Projeto 1 - Engenharia de Software** (versão CLI, v1.2) e evoluída na disciplina de **Projeto 2 - Engenharia de Software** para uma plataforma web completa (Web Engine, v2.0 — em desenvolvimento).

O sistema realiza varreduras ativas na rede, identifica serviços expostos coletando assinaturas de servidores (Banner Grabbing) e correlaciona as vulnerabilidades encontradas diretamente com a matriz global **MITRE ATT&CK v14** e o comportamento do **Nikto Spider**.

---

## 🛠️ Tecnologias e Pré-requisitos

Para que o projeto funcione corretamente, foi necessária a instalação e configuração dos seguintes componentes na máquina de desenvolvimento:

1. **Python 3.10+**: Linguagem de programação base utilizada no projeto.
2. **Npcap (Windows) / Libpcap (Linux/Mac)**: Biblioteca de captura de pacotes brutos. *Crucial para que a biblioteca Scapy consiga interagir diretamente com a placa de rede.*
3. **Docker & Docker Compose (Opcional)**: Para execução conteinerizada e isolamento de ambiente.
4. **Git**: Ferramenta de controle de versão utilizada para gerenciar o código e publicar no GitHub.
5. **VS Code**: Ambiente de desenvolvimento (IDE) utilizado para codificação.

---

## 📦 Bibliotecas Utilizadas (Dependências)

O projeto foi construído utilizando o conceito de ambiente virtual isolado (`venv`) e depende das seguintes bibliotecas de terceiros:

**Núcleo original (Projeto 1 — CLI):**
- **Scapy (`pip install scapy`)**: Utilizada para manipulação, injeção e captura passiva de pacotes de rede (Camadas 2, 3 e 4).
- **Rich (`pip install rich`)**: Utilizada para construir a interface CLI avançada com tabelas, cores agressivas, painéis e barras de status em tempo real.

**Adicionadas na evolução Web (Projeto 2):**
- **SQLModel (`pip install sqlmodel`)**: ORM que une SQLAlchemy + Pydantic, usado para modelar e persistir os dados (usuários, dispositivos, relatórios) em SQLite.
- **bcrypt (`pip install bcrypt`)**: Geração e verificação de hash de senha dos usuários.
- **python-jose[cryptography] (`pip install python-jose[cryptography]`)**: Geração e validação de tokens JWT de sessão.
- **FastAPI (`pip install fastapi`)**: Framework assíncrono que expõe a API web da aplicação.
- **Uvicorn (`pip install "uvicorn[standard]"`)**: Servidor ASGI usado para rodar a aplicação FastAPI.
- **python-multipart (`pip install python-multipart`)**: Exigido pelo FastAPI para processar o formulário de login (`OAuth2PasswordRequestForm`).

---

## 🚀 Como Instalar e Executar

O NetGuard foi projetado para ser flexível, oferecendo suporte tanto para execução isolada em contêineres quanto para execução nativa multiplataforma. Escolha uma das opções abaixo:

### Opção 1: Execução via Docker (Recomendado para Homologação)

> ⚠️ A imagem Docker atual builda a versão CLI original (v1.2). A atualização do `docker-compose.yml`/`Dockerfile` para subir o servidor web (Uvicorn) está prevista para a Sprint 4 do cronograma.

O projeto possui suporte nativo a contêineres com acoplamento direto à interface de rede física (*host networking mode*), permitindo que o Scapy interaja com o tráfego real por dentro do contêiner.

Para buildar a imagem e disparar a aplicação, execute na raiz do projeto:

```
sudo docker-compose up --build
```

---

### Opção 2: Execução Nativa (Windows / Linux)

Caso o ambiente hospedeiro apresente restrições de baixo nível ou falhas no Daemon do Docker (comum em distribuições baseadas em Arch Linux devido a drivers de armazenamento ou módulos de Kernel), utilize o fluxo nativo:

1. **Clonar o Repositório**:

```
git clone https://github.com/lancelmo/NetGuard-CLI.git

cd NetGuard-CLI
```

2. **Instalar Dependências do Sistema (Apenas se estiver no Linux)**

- No Linux, o Python precisa da biblioteca nativa de captura de pacotes instalada no sistema operacional.
- No Arch Linux / Manjaro: `sudo pacman -S libpcap --noconfirm`
- No Ubuntu / Debian: `sudo apt update && sudo apt install libpcap-dev -y`

3. **Criar e Ativar o Ambiente Virtual (venv)**

- No Windows (PowerShell):

```
python -m venv venv

.\venv\Scripts\activate
```

- No Linux (Terminal/Zsh):

```
python -m venv venv

source venv/bin/activate
```

4. **Instalar as Dependências do Python**

```
pip install -r requirements.txt
```

5. **Executar a Aplicação (CLI original, Projeto 1)**

⚠️ IMPORTANTE (Requisito de Segurança): Como o software realiza escuta de tráfego na rede (Sniffing) e manipula pacotes brutos, o interpretador Python DEVE ser executado com privilégios de Administrador.

No Windows: Abra o Prompt/PowerShell como Administrador e rode:

```
python main.py
```

No Linux (Execução via Root da venv):

```
sudo ./venv/bin/python main.py
```

---

## 🌐 Web Engine (Projeto 2 — em desenvolvimento)

A evolução para plataforma web expõe as mesmas capacidades de auditoria através de uma API (FastAPI), com persistência em banco de dados e autenticação. Progresso atual: **Sprint 2 concluída** (banco de dados, autenticação, e migração do motor de varredura para rotas web).

### Configurar o banco de dados

```
python database.py
```

Cria o arquivo `netguard.db` (SQLite) com as tabelas `users`, `devices`, `scan_reports` e `sniffer_logs`.

### Criar o primeiro usuário (admin)

```
python auth.py criar_admin
```

### Subir o servidor

⚠️ Assim como a CLI, o servidor precisa de privilégios de Administrador (o scan de rede usa Scapy).

- No Windows: abra o PowerShell **como Administrador**, ative a venv, e rode:

```
uvicorn server:app --reload
```

- No Linux:

```
sudo ./venv/bin/uvicorn server:app --reload
```

O servidor sobe em `http://127.0.0.1:8000`. A documentação interativa (Swagger) fica disponível em `http://127.0.0.1:8000/docs`.

### Rotas disponíveis

| Rota | Método | Autenticação | Descrição |
|---|---|---|---|
| `/login` | POST | — | Autentica usuário/senha e retorna um token JWT |
| `/me` | GET | 🔒 | Retorna os dados do usuário autenticado (teste do token) |
| `/scan` | POST | 🔒 | Executa a auditoria interna (ARP + Port Scan) numa faixa de IP (ex: `192.168.1.0/24`), salva no banco e retorna o resultado **agrupado por porta**, com correlação **MITRE ATT&CK** e **score de risco** agregado |
| `/devices` | GET | 🔒 | Lista os dispositivos já mapeados em varreduras anteriores |
| `/reports` | GET | 🔒 | Lista o histórico de relatórios de varredura |

---

## 🏗️ Arquitetura de Módulos Operacionais

**Núcleo original (Projeto 1 — CLI):**
- `main.py`: Controlador central da interface (NetGuardController). Gerencia o fluxo do menu e a persistência em memória.
- `scanner.py`: Motor de varredura (ScannerEngine). Responsável pelo Reconhecimento ARP (RF01) e pelo Port Scanning com Banner Grabbing no estilo Nikto (RF02).
- `sniffer.py`: Módulo de monitoramento contínuo (SnifferModule). Captura o tráfego IP de forma promíscua, identificando fabricantes via endereço MAC e classificando a segurança dos protocolos em tempo real (RF03/RF04).
- `reports.py`: Gerenciador de relatórios (ReportManager). Classifica os dados e exporta uma auditoria em JSON integrada com inteligência contra ameaças baseada no Framework MITRE ATT&CK (RF05).
- `models.py`: Contém o DTO (DeviceDTO) estruturado para transferência limpa de dados entre módulos.

**Evolução Web (Projeto 2):**
- `database.py`: Conexão SQLModel/SQLite e criação das tabelas.
- `db_models.py`: Modelos de persistência (`User`, `Device`, `ScanReport`, `SnifferLog`), conforme o esquema ER da especificação.
- `auth.py`: Hash de senha (bcrypt) e geração/validação de tokens JWT.
- `server.py`: Servidor FastAPI — rotas de login e das funcionalidades web.
- `scan_service.py`: Camada de serviço que conecta o `ScannerEngine`/`ReportManager` originais ao banco de dados, agrupando o resultado do scan por porta e calculando o score de risco.

---

## 🧪 Guia de Testes das Funcionalidades (Interface CLI)

Ao iniciar a aplicação como Administrador, o operador terá acesso a um menu interativo com as seguintes opções para validação dos Requisitos Funcionais (RF):

- **Opção 1 - Reconhecimento de Ativos (Scan ARP)**: Realiza uma varredura veloz baseada em pacotes ARP ocultos para mapear os IPs e MACs ativos na rede local.
- **Opção 2 - Varredura de Portas e Banner Grabbing**: Executa um Port Scan direcionado nos alvos descobertos, extraindo assinaturas de serviços (estilo Nikto Spider) nas portas críticas de rede (21, 22, 80, 443, 445, 3306).
- **Opção 3 - Exportar Auditoria Threat Intelligence (JSON)**: Consolida todos os dados em memória e gera o arquivo `auditoria_cyber_intelligence.json` na raiz do projeto, contendo a análise heurística de risco cruzada com a matriz global MITRE ATT&CK v14.
- **Opção 4 - Monitoramento de Tráfego ao Vivo (Sniffer)**: Coloca a placa de rede em Modo Promíscuo para capturar e classificar pacotes IP em tempo real na tela, apontando tráfego seguro (criptografado) ou gerando alertas (`[ALERT]`) para protocolos em texto claro.
- **Opção 5 ou 0 - Sair**: Encerra a execução do motor com segurança.

---

## 🗺️ Progresso do Projeto 2 (Sprints)

- [x] **Sprint 1** — Especificação técnica, arquitetura, modelagem ER e planejamento
- [x] **Sprint 2** — Back-end e autenticação: banco de dados (SQLModel), autenticação (bcrypt + JWT), servidor FastAPI, migração do `ScannerEngine` para rota web (agrupado por porta + MITRE + score de risco)
- [ ] **Sprint 3** — Front-end responsivo (Bootstrap/Jinja2), dashboard de dispositivos e scan pela interface
- [ ] **Sprint 4** — Integração Docker multiplataforma e testes de ponta a ponta
