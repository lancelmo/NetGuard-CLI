"""
scan_service.py

Camada de serviço que conecta o ScannerEngine/ReportManager (já
existentes no CLI) ao banco de dados web. 

Agora agrupa o resultado do scan, anteriormente mostrava dados repetidos só que em dispositivos separados,
agora mostra por porta (não por dispositivo), com a correlação MITRE ATT&CK que
o reports.py já calculava, mais um score de risco agregado.
"""

from datetime import datetime
import ipaddress
import logging
from typing import List, Dict, Any

from sqlmodel import Session, select
from scapy.all import conf

from scanner import ScannerEngine
from reports import ReportManager
from db_models import Device, ScanReport

# O Scapy tenta enviar o pacote ARP em mais de uma interface de rede
# quando a máquina tem várias ativas (Wi-Fi, VMware, Wi-Fi Direct, etc.).
# Isso pode gerar um erro "Error sending packets" numa interface
# secundária mesmo quando a interface principal (correta) já respondeu
# com sucesso. É um erro não-fatal e não afeta o resultado do scan —
# aqui só silenciamos esse log de ruído específico do Scapy.
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)

# Peso de severidade por porta, usado para compor o score de risco.
# Baseado no mesmo racional de impacto que já existe no reports.py
# (ex: SMB/MySQL = movimento lateral/exfiltração = mais crítico).
SEVERITY_WEIGHT = {
    21: ("Alto", 30),    # FTP - credenciais em texto claro
    22: ("Médio", 15),   # SSH - seguro, mas alvo de força bruta
    80: ("Baixo", 5),    # HTTP - exposição normal, sem TLS
    443: ("Baixo", 5),   # HTTPS - exposição normal, esperado
    445: ("Alto", 30),   # SMB - movimento lateral / exploits críticos
    3306: ("Alto", 30),  # MySQL - exfiltração de dados
}
DEFAULT_SEVERITY = ("Médio", 15)


def _selecionar_interface_correta(target_range: str) -> None:
    """
    Corrige um problema conhecido do Scapy no Windows: em máquinas com
    mais de uma interface de rede (Wi-Fi, Ethernet, adaptadores virtuais
    de VPN/Docker/loopback), ele pode escolher a interface errada por
    padrão, causando erro ao montar o pacote ARP.

    Aqui, resolvemos qual interface real deve ser usada baseado na
    própria faixa de IP informada, e fixamos isso no Scapy antes do scan.
    """
    try:
        network = ipaddress.ip_network(target_range, strict=False)
        # Usa um IP dentro da faixa (ex: o primeiro host) só para
        # perguntar ao Scapy "por qual interface eu chegaria nesse IP?"
        hosts = list(network.hosts())
        probe_ip = str(hosts[0]) if hosts else str(network.network_address)

        iface, _addr, _gw = conf.route.route(probe_ip)
        conf.iface = iface
    except Exception:
        # Se não conseguir resolver, deixa o Scapy tentar o comportamento
        # padrão (não interrompe o scan por causa disso).
        pass


def run_scan_and_persist(target_range: str, session: Session) -> Dict[str, Any]:
    """
    Executa o ARP scan + port scan (auditoria interna), agrupa o
    resultado por porta com correlação MITRE, calcula o score de
    risco, salva tudo no banco e retorna o resultado agrupado.
    """
    _selecionar_interface_correta(target_range)

    engine = ScannerEngine(target_range)
    report_manager = ReportManager()

    discovered = engine.arp_scan()  # lista de DeviceDTO (ip, mac)

    # port_key -> {"ips": set(...), "banners": [...], "mitre": {...} }
    ports_grouped: Dict[int, Dict[str, Any]] = {}

    for dto in discovered:
        vendor = report_manager._identificar_fabricante_local(dto.mac)

        # Upsert do dispositivo (por mac_address)
        existing = session.exec(
            select(Device).where(Device.mac_address == dto.mac)
        ).first()
        if existing:
            existing.ip_address = dto.ip
            existing.vendor = vendor
            existing.last_seen = datetime.utcnow()
            session.add(existing)
        else:
            session.add(Device(
                ip_address=dto.ip,
                mac_address=dto.mac,
                vendor=vendor,
                last_seen=datetime.utcnow(),
            ))

        open_ports = engine.port_scan(dto.ip)
        for item in open_ports:
            porta = item["porta"]
            banner = item["banner_detectado"]

            if porta not in ports_grouped:
                mitre_info = report_manager._obter_dica_seguranca(porta, banner)
                severidade, peso = SEVERITY_WEIGHT.get(porta, DEFAULT_SEVERITY)
                ports_grouped[porta] = {
                    "porta": porta,
                    "servico": mitre_info["servico"],
                    "severidade": severidade,
                    "peso": peso,
                    "mitre_tactica": mitre_info["mitre_tactique"],
                    "mitre_tecnica": mitre_info["mitre_technique"],
                    "impacto_seguranca": mitre_info["impacto_seguranca"],
                    "dispositivos_afetados": [],
                }
            ports_grouped[porta]["dispositivos_afetados"].append(dto.ip)

    session.commit()

    # Monta as duas listas que vão pro banco (open_ports e mitre_tactics)
    # já no formato agrupado, sem repetir a mesma info por dispositivo.
    open_ports_payload: List[Dict[str, Any]] = []
    mitre_payload: List[Dict[str, Any]] = []
    risk_score = 0

    for porta, dados in sorted(ports_grouped.items()):
        open_ports_payload.append({
            "porta": dados["porta"],
            "servico": dados["servico"],
            "severidade": dados["severidade"],
            "dispositivos_afetados": dados["dispositivos_afetados"],
        })
        mitre_payload.append({
            "porta": dados["porta"],
            "mitre_tactica": dados["mitre_tactica"],
            "mitre_tecnica": dados["mitre_tecnica"],
            "impacto_seguranca": dados["impacto_seguranca"],
        })
        risk_score += dados["peso"]

    risk_score = min(100, risk_score)

    scan_report = ScanReport(
        target_ip=target_range,
        open_ports=open_ports_payload,
        mitre_tactics=mitre_payload,
        created_at=datetime.utcnow(),
    )
    session.add(scan_report)
    session.commit()
    session.refresh(scan_report)

    return {
        "scan_report_id": scan_report.id,
        "dispositivos_encontrados": len(discovered),
        "score_de_risco": risk_score,
        "portas_agrupadas": open_ports_payload,
        "correlacao_mitre": mitre_payload,
    }
