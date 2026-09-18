"""
sniffer_service.py

Camada de serviço que conecta o SnifferModule (já existente no CLI,
sniffer.py) ao WebSocket do front-end. Arquivo novo — não altera
sniffer.py, só reaproveita a identificação de fabricante dele.

Diferença importante em relação ao CLI original: aqui só os pacotes
classificados como INSEGURO ou CRÍTICO são enviados/persistidos —
o stream bruto de todo pacote (como o CLI faz) inundaria a tela no
navegador. Essa é a melhoria de agregação que já havíamos decidido
aplicar no sniffer.
"""

import queue
import threading
from datetime import datetime

from scapy.all import sniff, TCP, UDP, IP

from sniffer import SnifferModule

_vendor_lookup = SnifferModule()


class WebSnifferSession:
    """Uma sessão de captura, uma por conexão WebSocket ativa.

    mode="alerts" (padrão): só tráfego inseguro/crítico é enviado —
    evita poluir a tela em redes com muito tráfego.
    mode="all": todo o tráfego IP classificado é enviado (incluindo
    HTTPS/SSH seguros e DNS), útil para demonstrar que a classificação
    também reconhece tráfego seguro, não só os alertas.
    """

    def __init__(self, mode: str = "alerts"):
        self.mode = mode if mode in ("alerts", "all") else "alerts"
        self.stop_event = threading.Event()
        self.alert_queue = queue.Queue()

    def _handle_packet(self, packet):
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_mac = packet.src if hasattr(packet, "src") else None
        fabricante, _tipo = _vendor_lookup._identificar_dispositivo(src_mac)

        protocolo = "OUTRO"
        status = "N/A"

        if packet.haslayer(TCP):
            sport, dport = packet[TCP].sport, packet[TCP].dport
            if 443 in (sport, dport):
                protocolo, status = "HTTPS", "SEGURO"
            elif 80 in (sport, dport):
                protocolo, status = "HTTP", "INSEGURO"
            elif 22 in (sport, dport):
                protocolo, status = "SSH", "SEGURO"
            elif 21 in (sport, dport):
                protocolo, status = "FTP", "INSEGURO"
            elif 445 in (sport, dport):
                protocolo, status = "SMB", "CRÍTICO"
            else:
                return  # porta TCP não classificada — ignora (mesmo nos dois modos)
        elif packet.haslayer(UDP):
            sport, dport = packet[UDP].sport, packet[UDP].dport
            if 53 in (sport, dport):
                protocolo, status = "DNS", "N/A"
            else:
                return
        else:
            return

        is_alert = status in ("INSEGURO", "CRÍTICO")

        # No modo "alerts", só o que é inseguro/crítico entra na fila.
        # No modo "all", tudo que foi classificado acima entra.
        if self.mode == "alerts" and not is_alert:
            return

        self.alert_queue.put({
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": protocolo,
            "alert_type": status,
            "vendor": fabricante,
            "timestamp": datetime.utcnow().isoformat(),
            "is_alert": is_alert,
        })

    def run(self):
        sniff(
            filter="ip",
            prn=self._handle_packet,
            store=0,
            stop_filter=lambda pkt: self.stop_event.is_set(),
        )

    def stop(self):
        self.stop_event.set()
