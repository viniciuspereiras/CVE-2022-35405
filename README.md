# CVE-2022-35405
- [My blog post](https://bigous.me/2022/09/06/CVE-2022-35405.html)
- [Nuclei template](https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2022/CVE-2022-35405.yaml)
- [Other article](https://xz.aliyun.com/t/11578)
### ManageEngine PAM360 and Password Manager Pro unauthenticated remote code execution vulnerability PoC (Access Manager Plus authenticated only :\)
| Product Name         | Affected Version(s)    | Default port |
|----------------------|------------------------|--------------|
| PAM360               | 5.5 (5500) and below   |   8282       |
| Password Manager Pro | 12.1 (12100) and below |   7272
| Access Manager Plus (authenticated)  | 4.3 (4302) and below   | 9292 |

Some custom installations use port 80 or 443.

#### Usage:
```bash
python3 CVE-2022-33405.py -u <url> -p <port> --jar '/path/to/ysoserial.jar' -c <command payload>
```
