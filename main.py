from ipProcess import *
from hostDiscovery import *
from portProcess import *
from portScanner import *
from bannerDetector import *
import os,platform,time

#清屏
def clear_screen():
    if platform.system().lower() == "windows":
        os.system('cls')
    else:
        os.system('clear')

def main_ui():
    while True:
        clear_screen()
        print("---------------------")
        print("|  网络扫描工具v1.0  |")
        print("---------------------")
        print("|    1.主机发现     |")
        print("|    2.端口扫描     |")
        print("|    3.banner探测   |")
        print("|    4.退出程序     |")
        print("---------------------")
        try:
            choice=input("输入数字选择功能:")
            if choice=='1':
                host_ui()
            elif choice=='2':
                port_ui()
            elif choice=='3':
                banner_detect=bannerDetector()
                banner_detect.banner_detect()
                input("按回车键继续...")
            elif choice=='4':
                print("感谢使用,程序退出...")
                time.sleep(1)
                break
            else:
                print("无效选择,请重新输入!!!")
                input("按回车键继续...")
        except ValueError:
            print("请输入有效的数字!!!")
            input("按回车键继续...")
        except KeyboardInterrupt:
            print("\n程序被用户中断")
            break


def host_ui():
    while True:
        clear_screen()
        print("--------------------")
        print("|    主机发现模块    |")
        print("--------------------")
        print("|    1.arp扫描      |")
        print("|    2.icmp扫描     |")
        print("|   3.返回上一级    |")
        print("--------------------")
        try:
            host_discover=hostDiscovery()
            choice=input("输入数字选择功能:")
            if choice=='1':
                print("进行主机arp扫描...")
                host_discover.arp_scan_batch()
                input("按回车键继续...")
                break
            elif choice=='2':
                print("进行主机icmp扫描...")
                host_discover.icmp_scan_batch()
                input("按回车键继续...")
                break
            elif choice=='3':
                break
            else:
                print("无效选择,请重新输入!!!")
                input("\n按回车键继续...")
        except ValueError:
            print("请输入有效的数字!!!")
            input("\n按回车键继续...")
        except KeyboardInterrupt:
            break

def port_ui():
    while True:
        clear_screen()
        print("----------------------")
        print("|    端口扫描模块     |")
        print("----------------------")
        print("|    1.tcp半开放扫描  |")
        print("|    2.tcp全开放扫描  |")
        print("|    3.udp扫描        |")
        print("|    4.返回上一级     |")
        print("----------------------")
        try:
            port_scan=portScanner()
            choice=input("输入数字选择功能:")
            if choice=='1':
                print("进行端口tcp半开放扫描...")
                port_scan.tcp_syn_scan_batch()
                input("按回车键继续...")
                break
                
            elif choice=='2':
                print("进行端口tcp全开放扫描...")
                port_scan.tcp_connect_scan_batch()
                input("按回车键继续...")
                break
                
            elif choice=='3':
                print("进行端口udp扫描...")
                port_scan.udp_scan_batch()
                input("按回车键继续...")
                break
                
            elif choice=='4':
                break
            
            else:
                print("无效选择,请重新输入!!!")
                input("\n按回车键继续...")
        except ValueError:
            print("请输入有效的数字!!!")
            input("\n按回车键继续...")
        except KeyboardInterrupt:
            break
                
def main():
    try:
        main_ui()
    except KeyboardInterrupt:
        print("\n程序被用户中断,再见...")
    except Exception as e:
        print(f"\n程序发生错误: {e}")
if __name__=="__main__":
    main()