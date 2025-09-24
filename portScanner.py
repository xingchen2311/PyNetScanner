from scapy.all import *
from typing import List
from portProcess import *
from ipProcess import *
from scapy.layers.inet import IP,ICMP,TCP,UDP
from random import randint
class portScanner:
    def __init__(self, timeout=3, retries=1):
        self.timeout = timeout
        self.retries = retries
        self.results = []
        
    #随机生成源端口
    def generate_random_port(self):
        return random.randint(1024,65535)
    
    # TCP半开放扫描（SYN扫描）
    def tcp_syn_scan_batch(self) -> List[str]:
        ip_list = ipProcess.ip_input_and_process()
        port_list = portProcess.port_input_and_process()
        
        print(f"解析为 {len(ip_list)} 个目标，{len(port_list)} 个端口,正在进行TCP SYN扫描...")
        
        open_ports_by_host = {}  # 存储每个主机的开放端口
        
        try:
            # 准备所有SYN包
            syn_packets = []
            for ip in ip_list:
                for port in port_list:
                    sport = self.generate_random_port()
                    packet = IP(dst=ip)/TCP(sport=sport, dport=port, flags="S")
                    syn_packets.append(packet)
            
            # 批量发送并接收响应
            answered, unanswered = sr(syn_packets, timeout=self.timeout, 
                                     retry=self.retries, verbose=False)
            
            # 处理响应
            for sent, received in answered:
                ip = sent[IP].dst
                port = sent[TCP].dport
                
                if received.haslayer(TCP):
                    if received.getlayer(TCP).flags == 0x12:  # SYN-ACK
                        # 发送RST关闭连接（半开放扫描特点）
                        send_rst = sr(IP(dst=ip)/TCP(sport=sent[TCP].sport, dport=port, flags="R"), 
                                     timeout=1, verbose=0)
                        result = f"{ip}:{port} - 开放"
                        print(f"发现开放TCP端口: {ip}:{port}")
                        
                        # 记录开放端口
                        if ip not in open_ports_by_host:
                            open_ports_by_host[ip] = []
                        open_ports_by_host[ip].append(f"TCP:{port}")
                        
                    elif received.getlayer(TCP).flags == 0x14:  # RST-ACK
                        result = f"{ip}:{port} - 关闭"
                        print(f"TCP端口关闭: {ip}:{port}")
                else:
                    result = f"{ip}:{port} - 未知响应类型"
                    print(f"未知响应: {ip}:{port}")
            
            # 处理未响应的包
            for sent in unanswered:
                ip = sent[IP].dst
                port = sent[TCP].dport
                result = f"{ip}:{port} - 过滤/丢弃"
                print(f"TCP无响应: {ip}:{port}")
                
        except KeyboardInterrupt:
            print("\n用户中断扫描")
            return
        except Exception as e:
            print(f"TCP扫描过程出错: {e}")
            return
        
        # 输出结果摘要
        self._print_summary(open_ports_by_host, len(ip_list), len(port_list), "TCP")
        return self.results
    
    # TCP全开放扫描（Connect扫描）
    def tcp_connect_scan_batch(self) -> List[str]:
        ip_list = ipProcess.ip_input_and_process()
        port_list = portProcess.port_input_and_process()
        
        print(f"解析为 {len(ip_list)} 个目标，{len(port_list)} 个端口，正在TCP全连接扫描...")
        
        open_ports_by_host = {}  # 存储每个主机的开放端口
        
        try:
            # 准备所有SYN包
            syn_packets = []
            for ip in ip_list:
                for port in port_list:
                    sport = self.generate_random_port()
                    packet = IP(dst=ip)/TCP(sport=sport, dport=port, flags="S")
                    syn_packets.append(packet)
            
            # 批量发送SYN包并接收响应
            answered, unanswered = sr(syn_packets, timeout=self.timeout, 
                                     retry=self.retries, verbose=False)
            
            # 处理响应 - 完成三次握手
            for sent, received in answered:
                ip = sent[IP].dst
                port = sent[TCP].dport
                
                if received.haslayer(TCP):
                    if received.getlayer(TCP).flags == 0x12:  # SYN-ACK
                        # 发送ACK完成三次握手（全开放扫描特点）
                        ack_packet = IP(dst=ip)/TCP(sport=sent[TCP].sport, dport=port, 
                                                  seq=received[TCP].ack, ack=received[TCP].seq + 1, flags="A")
                        send(ack_packet, verbose=0)
                        
                        # 然后发送FIN或RST关闭连接
                        fin_packet = IP(dst=ip)/TCP(sport=sent[TCP].sport, dport=port, 
                                                  seq=received[TCP].ack, ack=received[TCP].seq + 1, flags="FA")
                        send(fin_packet, verbose=0)
                        
                        result = f"{ip}:{port} - 开放"
                        self.results.append(result)
                        print(f"发现开放TCP端口: {ip}:{port}")
                        
                        # 记录开放端口
                        if ip not in open_ports_by_host:
                            open_ports_by_host[ip] = []
                        open_ports_by_host[ip].append(f"TCP:{port}")
                        
                    elif received.getlayer(TCP).flags == 0x14:  # RST-ACK
                        result = f"{ip}:{port} - 关闭"
                        self.results.append(result)
                        print(f"TCP端口关闭: {ip}:{port}")
                else:
                    result = f"{ip}:{port} - 未知响应类型"
                    self.results.append(result)
                    print(f"未知响应: {ip}:{port}")
            
            # 处理未响应的包
            for sent in unanswered:
                ip = sent[IP].dst
                port = sent[TCP].dport
                result = f"{ip}:{port} - 过滤/丢弃"
                self.results.append(result)
                print(f"TCP无响应: {ip}:{port}")
                
        except KeyboardInterrupt:
            print("\n用户中断扫描")
            self.results.append("扫描被用户中断")
        except Exception as e:
            error_msg = f"TCP扫描过程出错: {e}"
            print(error_msg)
            self.results.append(error_msg)
        
        # 输出结果摘要
        self._print_summary(open_ports_by_host, len(ip_list), len(port_list), "TCP")
        return self.results
    
    # UDP扫描
    def udp_scan_batch(self) -> List[str]:
        ip_list = ipProcess.ip_input_and_process()
        port_list = portProcess.port_input_and_process()
        
        print(f"解析为 {len(ip_list)} 个目标，{len(port_list)} 个端口，正在UDP扫描...")
        
        open_ports_by_host = {}  # 存储每个主机的开放端口
        
        try:
            # 准备所有UDP包
            udp_packets = []
            for ip in ip_list:
                for port in port_list:
                    # 发送空的UDP数据包
                    packet = IP(dst=ip)/UDP(dport=port)
                    udp_packets.append(packet)
            
            # 批量发送UDP包并接收响应
            answered, unanswered = sr(udp_packets, timeout=self.timeout, 
                                     retry=self.retries, verbose=False)
            
            # 处理响应
            for sent, received in answered:
                ip = sent[IP].dst
                port = sent[UDP].dport
                
                if received.haslayer(ICMP):
                    # ICMP端口不可达错误，说明端口关闭
                    if received[ICMP].type == 3 and received[ICMP].code == 3:
                        result = f"{ip}:{port} - 关闭"
                        self.results.append(result)
                        print(f"UDP端口关闭: {ip}:{port}")
                    else:
                        # 其他ICMP错误
                        result = f"{ip}:{port} - 过滤/阻挡"
                        self.results.append(result)
                        print(f"UDP端口过滤: {ip}:{port}")
                elif received.haslayer(UDP):
                    # 收到UDP响应，说明端口可能开放
                    result = f"{ip}:{port} - 开放"
                    self.results.append(result)
                    print(f"发现开放UDP端口: {ip}:{port}")
                    
                    # 记录开放端口
                    if ip not in open_ports_by_host:
                        open_ports_by_host[ip] = []
                    open_ports_by_host[ip].append(f"UDP:{port}")
                else:
                    result = f"{ip}:{port} - 未知响应类型"
                    self.results.append(result)
                    print(f"未知UDP响应: {ip}:{port}")
            
            # 处理未响应的包 - 无响应可能表示端口开放
            for sent in unanswered:
                ip = sent[IP].dst
                port = sent[UDP].dport
                result = f"{ip}:{port} - 可能开放(无响应)"
                self.results.append(result)
                print(f"UDP端口可能开放: {ip}:{port}")
                
                # 记录可能开放的端口
                if ip not in open_ports_by_host:
                    open_ports_by_host[ip] = []
                open_ports_by_host[ip].append(f"UDP:{port}(可能开放)")
                
        except KeyboardInterrupt:
            print("\n用户中断扫描")
            self.results.append("扫描被用户中断")
        except Exception as e:
            error_msg=f"UDP扫描过程出错: {e}"
            print(error_msg)
            self.results.append(error_msg)
        
        # 输出结果摘要
        self._print_summary(open_ports_by_host, len(ip_list), len(port_list), "UDP")
        return self.results
    
    # 结果摘要输出,文件保存
    def _print_summary(self, open_ports_by_host, ip_count, port_count, protocol):
        print(f"\n{protocol}扫描完成! 共扫描 {ip_count * port_count} 个目标:")
        
        # 输出每个主机的开放端口
        print("开放端口:")
        for host, ports in open_ports_by_host.items():
            ports_str = ",".join(ports)
            print(f"host: {host} {protocol.lower()}port:{ports_str}")
            self.results.append(f"host: {host} {protocol.lower()}port:{ports_str}")
        
        #保存文件
        choice=input("是否将结果保存到文件?(Y/N):")
        if choice in ['Y','y']:
            try:
                with open(f"./{protocol.lower()}_portscan_results.txt","w",encoding="utf-8") as f:
                    for result in self.results:
                        f.write(result+"\n")
                print("保存成功!!!")
            except Exception as e:
                print(f"保存出错:{e}")
                return
        else:
            return
            
                
                
        