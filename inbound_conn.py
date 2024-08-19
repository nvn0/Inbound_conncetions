from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP, conf
import socket
import subprocess
from datetime import datetime
import platform
import requests

#local_ip = "172.30.14.90"


# Dicionário para armazenar a contagem de bytes por porta
traffic_counter = {}


def get_local_ip():
    # Obtém o IP local da máquina em linux
     if platform.system() == "Linux":
        result = subprocess.run("ifconfig | grep broadcast | awk '{print $2}'", shell=True, capture_output=True, text=True)
        local_ip = result.stdout.strip()
        #print("Local IP:", local_ip)
        return local_ip
    

def get_public_ip():
    pub_ip = requests.get("https://icanhazip.com").content
    return pub_ip.decode().rstrip()
    

   
public_ip = get_public_ip()
local_ip = get_local_ip()
print(f"Local IP: {local_ip}       Public IP: {public_ip}")
print("----------------------------------------------------------")
print("Inbound Connections:")


def packet_callback(packet):
    #local_ip = get_local_ip()
    
    
   
    # Verifica se o pacote tem uma camada IP e não é proveniente do IP local
    if IP in packet and packet[IP].src != local_ip:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Obtém a hora atual
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        
        # Verifica se o pacote tem uma camada TCP ou UDP
        if TCP in packet:
            protocol = "TCP"
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
            packet_size = len(packet)
        elif UDP in packet:
            protocol = "UDP"
            port_src = packet[UDP].sport
            port_dst = packet[UDP].dport
            packet_size = len(packet)
        elif ICMP in packet:
            protocol = "ICMP"
            port_src = "N/A"
            port_dst = "N/A"
            packet_size = len(packet)
        else:
            protocol = "Other"
            port_src = "N/A"
            port_dst = "N/A"
            packet_size = len(packet)
            
            
        # Atualiza o contador de tráfego para as portas
        if protocol in ["TCP", "UDP"]:
            port = port_dst if port_dst != "N/A" else port_src
            if port != "N/A":
                if port not in traffic_counter:
                    traffic_counter[port] = 0
                traffic_counter[port] += len(packet)
        
        #print(f"[{timestamp}] - IP de origem: {ip_src:<15} | Porta de origem: {port_src:<5} | Porta de destino: {port_dst:<5} | Protocolo: {protocol:<5} | Data: {packet_size} bytes")
        print(f"[{timestamp}] - IP de origem: {ip_src:<15} | Porta de origem: {port_src:<5} | Porta de destino: {port_dst:<5} | Protocolo: {protocol:<4} | Packet size: {packet_size:<5} bytes | Total Data (In this port): {traffic_counter.get(port_dst if port_dst != 'N/A' else port_src, 0):<5} bytes")
        
        #if port_src and port_dst:
            #print(f"IP de origem: {ip_src: <5}, Porta de origem: {port_src: <5}, IP de destino: {ip_dst: <5}, Porta de destino: {port_dst: <5}")
            #print(f"[{timestamp}] - IP de origem: {ip_src: <5}, Porta de origem: {port_src: <5}, Porta de destino: {port_dst: <5}, Protocolo: {protocol}")
        #elif port_dst:
        #    print(f"IP de origem: {ip_src}, Porta de destino: {port_dst}")
        #else:
            #print(f"IP de origem: {ip_src}, IP de destino: {ip_dst}, Porta de origem ou destino: Desconhecida")
            #print(f"IP de origem: {ip_src: <5}, Porta de origem: {port_src: <5}, IP de destino: {ip_dst: <5}, Porta de destino: {port_dst: <5}")
            #print(f"[{timestamp}] - IP de origem: {ip_src: <5}, Porta de origem: {port_src: <5}, Porta de destino: {port_dst: <5}, Protocolo: {protocol}")


# Captura de pacotes na interface 'eth0'. Ajustar conforme necessário.
sniff(iface='eth0', prn=packet_callback, filter="ip", store=0)
