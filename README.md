# NetGuard Cyber Defense Network Engine v1.2

Este projeto é uma ferramenta de auditoria de segurança e monitoramento de ativos de rede local em linha de comando (CLI), desenvolvida como projeto prático para a disciplina de **Projeto 1 - Engenharia de Software**. 

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

* **Scapy (`pip install scapy`)**: Utilizada para manipulação, injeção e captura passiva de pacotes de rede (Camadas 2, 3 e 4).
* **Rich (`pip install rich`)**: Utilizada para construir a interface CLI avançada com tabelas, cores agressivas, painéis e barras de status em tempo real.

---

## 🚀 Como Instalar e Executar

O NetGuard-CLI foi projetado para ser flexível, oferecendo suporte tanto para execução isolada em contêineres quanto para execução nativa multiplataforma. Escolha uma das opções abaixo:

### Opção 1: Execução via Docker (Recomendado para Homologação)
O projeto possui suporte nativo a contêineres com acoplamento direto à interface de rede física (*host networking mode*), permitindo que o Scapy interaja com o tráfego real por dentro do contêiner.

Para buildar a imagem e disparar a aplicação, execute na raiz do projeto:
```bash
sudo docker-compose up --build
```
---

### Opção 2: Execução Nativa (Windows / Linux)

Caso o ambiente hospedeiro apresente restrições de baixo nível ou falhas no Daemon do Docker (comum em distribuições baseadas em Arch Linux devido a drivers de armazenamento ou módulos de Kernel), utilize o fluxo nativo:

1. **Clonar o Repositório**:
```Bash
git clone [https://github.com/lancelmo/NetGuard-CLI.git](https://github.com/lancelmo/NetGuard-CLI.git)

cd NetGuard-CLI
```

2. **Instalar Dependências do Sistema (Apenas se estiver no Linux)**

* No Linux, o Python precisa da biblioteca nativa de captura de pacotes instalada no sistema operacional.

* No Arch Linux / Manjaro: sudo pacman -S libpcap --noconfirm

* No Ubuntu / Debian: sudo apt update && sudo apt install libpcap-dev -y

3. **Criar e Ativar o Ambiente Virtual (venv)**
* No Windows (PowerShell):

```PowerShell

python -m venv venv

.\venv\Scripts\activate
```

* No Linux (Terminal/Zsh):

```Bash

python -m venv venv

source venv/bin/activate
```

4. **Instalar as Dependências do Python**
```Bash

pip install scapy rich
```

5. **Executar a Aplicação**

⚠️ IMPORTANTE (Requisito de Segurança): Como o software realiza escuta de tráfego na rede (Sniffing) e manipula pacotes brutos, o interpretador Python DEVE ser executado com privilégios de Administrador.

No Windows: Abra o Prompt/PowerShell como Administrador e rode:

```PowerShell

python main.py
```

No Linux (Execução via Root da venv):

```Bash
sudo ./venv/bin/python main.py
```

---

 ***Arquitetura de Módulos Operacionais***

* main.py: Controlador central da interface (NetGuardController). Gerencia o fluxo do menu e a persistência em memória.

* scanner.py: Motor de varredura (ScannerEngine). Responsável pelo Reconhecimento ARP (RF01) e pelo Port Scanning com Banner Grabbing no estilo Nikto (RF02).

* sniffer.py: Módulo de monitoramento contínuo (SnifferModule). Captura o tráfego IP de forma promíscua, identificando fabricantes via endereço MAC e classificando a segurança dos protocolos em tempo real (RF03/RF04).

* reports.py: Gerenciador de relatórios (ReportManager). Classifica os dados e exporta uma auditoria em JSON integrada com inteligência contra ameaças baseada no Framework MITRE ATT&CK (RF05).

* models.py: Contém o DTO (DeviceDTO) estruturado para transferência limpa de dados entre módulos.

---

***Guia de Testes das Funcionalidades (Interface CLI)***

Ao iniciar a aplicação como Administrador, o operador terá acesso a um menu interativo com as seguintes opções para validação dos Requisitos Funcionais (RF):

* Opção 1 - Reconhecimento de Ativos (Scan ARP): Realiza uma varredura veloz baseada em pacotes ARP ocultos para mapear os IPs e MACs ativos na rede local.

* Opção 2 - Varredura de Portas e Banner Grabbing: Executa um Port Scan direcionado nos alvos descobertos, extraindo assinaturas de serviços (estilo Nikto Spider) nas portas críticas de rede (21, 22, 80, 443, 445, 3306).

* Opção 3 - Exportar Auditoria Threat Intelligence (JSON): Consolida todos os dados em memória e gera o arquivo auditoria_cyber_intelligence.json na raiz do projeto, contendo a análise heurística de risco cruzada com a matriz global MITRE ATT&CK v14.

* Opção 4 - Monitoramento de Tráfego ao Vivo (Sniffer): Coloca a placa de rede em Modo Promíscuo para capturar e classificar pacotes IP em tempo real na tela, apontando tráfego seguro (criptografado) ou gerando alertas ([ALERT]) para protocolos em texto claro.

* Opção 5 ou 0 - Sair: Encerra a execução do motor com segurança.
