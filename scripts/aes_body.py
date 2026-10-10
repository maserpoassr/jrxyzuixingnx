#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""今日校园签到请求体 `bodyString` 的加解密方法。

协议
----
    bodyString = base64( AES-128-CBC-PKCS7( json(表单), key = fkey_cat ) )

    - 算法：AES-128-CBC，PKCS7 填充，输出 base64
    - IV  ：01 02 03 04 05 06 07 08 09 01 02 03 04 05 06 07
            （= bytes(range(1,10)) + bytes(range(1,8))）
    - key ：fkey_cat（16 字节 ASCII），见 get_fkey_cat.py

完整请求体（安卓原生）：
    {
      "systemName": "android", "systemVersion": "...", "model": "...",
      "deviceId": "...", "appVersion": "9.9.24", "lon": .., "lat": .., "userId": "...",
      "bodyString": "<上面的加密串>",
      "version": "first_v4", "calVersion": "firstv"
    }

“版本过低”的成因
----------------
服务端用 `fkey_cat` 解密 `bodyString`；若你用了**旧固定 key**（如 `abcdfe0987612345`
+AES-ECB），解密失败 → 服务端返回伪装报错 `{"code":"4","message":"今日校园版本过低"}`。
**换成 `fkey_cat` 后即可正常解密，进入业务层。**

用法
----
    python aes_body.py encrypt '{"signInstanceWid":"123"}'   # 打印 bodyString
    python aes_body.py decrypt '<bodyString>'                # 打印明文 JSON
    python aes_body.py demo                                  # 自测
"""
import base64
import json
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# 与 App 一致：IV = 01..09 01..07
AES_IV = bytes(range(1, 10)) + bytes(range(1, 8))
# 全平台固定密钥（见 get_fkey_cat.py）
FKEY_CAT = "hru89rwr87Nthifa"


def encrypt_body(form: dict, key: str = FKEY_CAT) -> str:
    """表单 dict -> bodyString（AES-CBC-PKCS7 + base64）。"""
    raw = json.dumps(form, ensure_ascii=False).encode("utf-8")
    return base64.b64encode(
        AES.new(key.encode("utf-8"), AES.MODE_CBC, AES_IV).encrypt(pad(raw, 16))
    ).decode()


def decrypt_body(body_string: str, key: str = FKEY_CAT) -> dict:
    """bodyString -> 表单 dict。"""
    raw = AES.new(key.encode("utf-8"), AES.MODE_CBC, AES_IV).decrypt(
        base64.b64decode(body_string))
    return json.loads(unpad(raw, 16).decode("utf-8"))


def _demo():
    form = {"signInstanceWid": "123456", "longitude": 0.0, "latitude": 0.0,
            "position": "示例地址", "signVersion": "1.0.0"}
    bs = encrypt_body(form)
    back = decrypt_body(bs)
    print("明文    :", json.dumps(form, ensure_ascii=False))
    print("bodyString:", bs)
    print("解密回读 :", json.dumps(back, ensure_ascii=False))
    assert back == form
    print("✅ 加解密自测通过")


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "encrypt":
        print(encrypt_body(json.loads(sys.argv[2])))
    elif len(sys.argv) >= 3 and sys.argv[1] == "decrypt":
        print(json.dumps(decrypt_body(sys.argv[2]), ensure_ascii=False))
    else:
        _demo()
