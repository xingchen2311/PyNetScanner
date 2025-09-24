from scapy.all import *
from typing import List
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP,ICMP
from ipProcess import *
class hostDiscovery:
    def __init__(self,timeout=3,retries=1):
        self.timeout=timeout
        self.retries=retries
        self.result=[]
    
    #arp扫描
    def arp_scan_batch(self) -> List[str]:
        network = ipProcess.ip_input_and_process()
        print(f"解析为 {len(network)} 个目标，正在批量扫描...")
    
        alive_hosts = []
    
        try:
            # 准备所有ARP请求包
            arp_packets = []
            for target in network:
                arp_request = ARP(pdst=target)
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_packets.append(broadcast / arp_request)
        
            # 批量发送并接收响应
            answered, unanswered = srp(arp_packets, timeout=3, verbose=False)
        
            # 处理响应
            for sent, received in answered:
                alive_hosts.append(received.psrc)
                print(f"发现主机: {received.psrc} ({received.hwsrc})")
            
        except KeyboardInterrupt:
            print("\n用户中断扫描")
        except Exception as e:
            print(f"扫描过程出错: {e}")
    
        # 显示结果
        print(f"\n扫描完成! 发现 {len(alive_hosts)} 台存活主机:")
        for i, host in enumerate(alive_hosts, 1):
            print(f"{i}. {host}")
        self.save_to_file('arp',alive_hosts)
        return alive_hosts
    
    #icmp扫描
    def icmp_scan_batch(self) -> List[str]:
        network = ipProcess.ip_input_and_process()
        print(f"解析为 {len(network)} 个目标，正在批量扫描...")
    
        alive_hosts = [] 
    
        try:
            # 准备所有ping数据包
            ping_packets = []
            for target in network:
                ping_packets.append(IP(dst=target)/ICMP())
        
            # 批量发送并接收响应
            answered, unanswered = sr(ping_packets, timeout=3, verbose=False)
        
            # 处理响应
            for sent, received in answered:
                alive_hosts.append(received.src)
                print(f"发现主机: {received.src}")
            
        except KeyboardInterrupt:
            print("\n用户中断扫描")
        except Exception as e:
            print(f"扫描过程出错: {e}")
    
        # 显示扫描结果摘要,保存到文件
        print(f"\n扫描完成! 发现 {len(alive_hosts)} 台存活主机:")
        for i, host in enumerate(alive_hosts, 1):
            print(f"  {i}. {host}")
            
        self.save_to_file('icmp',alive_hosts)
        return alive_hosts
    
    #保存文件
    def save_to_file(self,type:str,alive_hosts:List[str]):
        choice=input("是否将结果保存到文件?(Y/N):")
        if choice in ['Y','y']:
            try:
                with open(f"{type}_hostscan_results.txt","w",encoding="utf-8") as f:
                    f.write("存活主机:\n")
                    for result in alive_hosts:
                        f.write(result+"\n")
                print("保存成功!!!")
            except Exception as e:
                print(f"保存出错:{e}")
        else:
            return
        