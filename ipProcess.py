import ipaddress
import re
from typing import List
class ipProcess:
    #综合处理ip地址
    @staticmethod
    def ip_process(target_input:str)->List[str]:
        if not target_input:
            return []
        #首尾去空
        target_input=target_input.strip()
        
        if ',' in target_input:
            return ipProcess.comma_separated_ip_process(target_input)
        if '/' in target_input:
            return ipProcess.cidr_ip_process(target_input)
        if '-' in target_input and target_input.count('.')==3:
            return ipProcess.range_ip_process(target_input)
        
        return ipProcess.single_ip_process(target_input)
    
    #cidr格式ip处理,如192.168.1.0/24
    @staticmethod
    def cidr_ip_process(cidr:str)->List[str]:
        try:
            #使用ipaddress库实现cidr类型的ip转换
            network=ipaddress.ip_network(cidr,strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            raise ValueError(f"无效的CIDR格式:{cidr}")
        
    #范围ip处理,如192.168.1.0-100
    @staticmethod
    def range_ip_process(ip_range:str)->List[str]:
        #使用正则匹配格式
        match=re.match(r'^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$',ip_range)
        if not match:
            raise ValueError(f"无效的IP范围格式:{ip_range}")
        #提取正则匹配中的分组
        base_ip=match.group(1)
        start=int(match.group(2))
        end=int(match.group(3))
        
        if not (0<=start<=255 and 0<=end<=255):
            raise ValueError(f"IP范围必须在0-255之间:{ip_range}")
        if start>end:
            raise ValueError(f"起始IP不能大于结束IP:{ip_range}")
        return [f"{base_ip}{i}" for i in range(start,end+1)]
            
    #处理逗号分割的ip，如192.168.43.171,192.168.152.144
    @staticmethod
    def comma_separated_ip_process(targets:str)->List[str]:
        ip_list=[]
        for target in targets.split(','):
            target=target.strip()
            if target:
                ip_list.extend(ipProcess.ip_process(target))
        return ip_list
    
    #处理单个ip
    @staticmethod
    def single_ip_process(ip:str)->List[str]:
        try:
            ipaddress.ip_address(ip)
            return [ip]
        except ValueError:
            raise ValueError(f"无效的IP地址:{ip}")
    
    #用于ip输入并且处理
    @staticmethod
    def ip_input_and_process()->List[str]:
        ip=input("请输入ip(支持单个ip,cidr格式,以逗号分割,-形式的范围ip):")
        ip=ipProcess.ip_process(ip)
        return ip
    