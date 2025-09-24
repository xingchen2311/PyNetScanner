from typing import List,Union
import re
class portProcess:
    #端口输入和处理
    @staticmethod
    def port_input_and_process()->List[int]:
        port=input("请输入端口(支持单个端口,逗号分隔,以-的端口范围,回车使用默认端口):").strip()
        if not port:
            return portProcess.get_default_ports()
        else:
            return portProcess.port_process(port)
    
     
    #综合处理端口
    @staticmethod
    def port_process(port_input:str)->List[int]:
        port_input=port_input.strip()
        if not port_input:
            return portProcess.get_default_ports()
        
        if ',' in port_input:
            return portProcess.comma_separated_port_process(port_input)
        if '-' in port_input:
            return portProcess.range_port_process(port_input)
        
        return portProcess.single_port_process(port_input)
    
    #处理范围端口,如1-100
    @staticmethod
    def range_port_process(port_range:str)->List[int]:
        match=re.match(r'^(\d+)-(\d+)$',port_range)
        if not match:
            raise ValueError(f"无效的端口范围格式:{port_range}")
        
        #提取分组
        start=int(match.group(1))
        end=int(match.group(2))
        
        if not (0<=start<=65535 and 0<=end<=65535):
            raise ValueError(f"端口必须在0-65535之间:{port_range}")
        if start>end:
            raise ValueError(f"起始端口不能大于结束端口:{port_range}")
        
        return list(range(start,end+1))
    
    #处理逗号分割的端口，如80,443,3306
    @staticmethod
    def comma_separated_port_process(ports:str)->List[int]:
        port_list=[]
        
        for port in ports.split(','):
            port=port.strip()
            if port:
                port_list.extend(portProcess.port_process(port))
        return port_list
    
    #处理单个端口
    @staticmethod
    def single_port_process(port:str)->List[int]:
        try:
            port_num=int(port)
            if not(0<=port_num<=65535):
                raise ValueError(f"端口必须在0-65535之间:{port}")
            return [port_num]
        except ValueError:
            raise ValueError(f"无效的端口:{port}")
        
    #获取默认端口
    @staticmethod
    def get_default_ports()->list[int]:
        return [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080]