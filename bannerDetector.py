from ipProcess import *
from portProcess import *
import socket
class bannerDetector:
    def __init__(self, timeout=3):
        self.results = []
        self.timeout = timeout
        
    #banner探测
    def banner_detect(self):
        print("正在运行banner探测程序...")
        ip_list = ipProcess.ip_input_and_process()
        port_list = portProcess.port_input_and_process()
        
        print(f"开始banner探测,已解析的IP数量: {len(ip_list)}，端口数量: {len(port_list)}...")
        
        for ip in ip_list:
            for port in port_list:
                s = None
                try:
                    s = socket.socket()
                    s.settimeout(self.timeout)
                    s.connect((ip, port))
                    
                    # 根据端口发送不同的探测数据
                    if port == 80 or port == 443:
                        s.send(b"GET / HTTP/1.0\r\n\r\n")
                    elif port == 21:
                        s.send(b"USER anonymous\r\n")
                    else:
                        s.send(b"hhh\r\n")
                    
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    result = f"[成功] {ip}:{port} - {banner}"
                    print(result)
                    self.results.append(result)
                    
                except socket.timeout:
                    result = f"[超时] {ip}:{port}"
                    print(result)
                    self.results.append(result)
                except ConnectionRefusedError:
                    result = f"[拒绝] {ip}:{port}"
                    print(result)
                    self.results.append(result)
                except Exception as e:
                    result = f"[错误] {ip}:{port} - {str(e)}"
                    print(result)
                    self.results.append(result)
                finally:
                    if s:
                        s.close()
        
        print("\nbanner探测完成...")
        #保存文件
        choice=input("是否将结果保存到文件?(Y/N):")
        if choice in ['Y','y']:
            try:
                with open(f"./banner_detect_results.txt","w",encoding="utf-8") as f:
                    for result in self.results:
                        f.write(result+"\n")
                print("保存成功!!!")
            except Exception as e:
                print(f"保存出错:{e}")
                return
        else:
            return
        return self.results