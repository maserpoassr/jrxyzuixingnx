#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通用获取今日校园「签到 bodyString」AES 密钥 fkey_cat。

背景
----
今日校园 App 9.9.x 起，签到提交体 `bodyString` 不再用固定 key（旧的
`abcdfe0987612345` + AES-ECB 已废弃，用它会返回「今日校园版本过低」）。
新协议改为：
    bodyString = base64( AES-128-CBC-PKCS7( json(表单), key=fkey_cat ) )
其中 `fkey_cat` 由 `getSecretKey` 接口协商得到（本脚本完整复现）。

关键点
------
- `getSecretKey` **无需登录**，任意设备 id 均可调用；
- 返回的 `cpdailySecret / catSecret` 经实测为**全平台固定值**
  （不同设备、不同学校、不同账号都相同），因此 `fkey_cat` 也是**固定值**：
        catSecret = 9hriwfra
        fkey_cat  = interleave("h8r7uN8t" + catSecret) = hru89rwr87Nthifa
  —— 即：**密钥其实是全平台通用的常量**，但本脚本给出“从接口获取”的通用方法，
  以便服务端将来轮换密钥时仍可用。

用法
----
    python get_fkey_cat.py            # 调接口取 key 并打印
    python get_fkey_cat.py --offline  # 不联网，直接打印已知固定 key

依赖：requests, pycryptodome
"""
import argparse
import base64
import hashlib
import json
import uuid

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ---------------------------------------------------------------------------
# 协议常量
# ---------------------------------------------------------------------------
SECRET_PATH = "app/auth/dynamic/secret/getSecretKey/v-920"
SECRET_SALT = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"  # sha256("hello")
LOCAL_PREFIX_FKEY = "h8r7uN8t"   # 安卓 getfKey（提交 bodyString 用）
LOCAL_PREFIX_CKEY = "f9akfyUe"   # 安卓 getcKey（登录请求体用）
HOSTS = ("https://mobile.campushoy.com/", "https://data-xxt.aichaoxing.com/")

# 已知固定值（实测：全平台一致；接口轮换后可能变化，届时用本脚本重新取）
KNOWN = {"cpdailySecret": "Yn9g6T5R", "catSecret": "9hriwfra",
         "fkey_cat": "hru89rwr87Nthifa", "ckey_cpdaily": "fafUY9659kyengTR"}

# getSecretKey 的 RSA 公私钥（明文内嵌，来源：开源项目 shixi-main）
PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCpwqE77zx+WexQWf1qDzb8EGey
et7VO78JiCDrZLcesaGjN5B8s66bMCfcn9R3GN25/EA3lFPI86hgluMPT6X1rneW
QRdKMaFWtxZLc+0Gdkf8zvdPf3rcYt6VjPnq3Hu1iSdytD8SIuTcSGFoPctId7jZ
zEjMjj74mnu3WtihZQIDAQAB
-----END PUBLIC KEY-----"""

PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKcyZ9yEReNLggED
LYqJVXKF4ZNDp/9sET7D3Dt7VZJKH8iK+KqjozEvT16E1RYpfjTmzXcGIbicVH6k
Htzy14+kzh8v28fY/a8Vd9Ot9v+eT6Jlze3uw2HsyFbad9Pl8x8d5rjMp8xHHXU+
qLvKiEzOmTvB+MDTyAnhPc42Q85HAgMBAAECgYAdny2NgRXMtkT7HvADml88IgIc
ECGEfEX148dx9mDrwRwucIir2r//58zdBxWljoZgov+F9d0lkvTZVwRsys1rySqp
BpDUB+WIQuYMHGqrf4ByZ+136TsSyXuKQ7PzOJ22HXnjth8QANS2ulFY9nE+ZpB8
9vEBoatDkJ9dx2TZ6QJBANvNYkchnkqAjXxYD5A///gQ1LZ2JLY4HB7WzIFRQNft
IXUmfyEWPYSpTdIroWoNInejJNZJStAFT2Bfq/IaN70CQQDCuzz7NOmq2iuqI20E
GY4qDMGjcJJT7ZWmeGRVADwKaLS4VrifZy201ZJxwaqTaFb9wd45whncaDz22S+t
QGxTAkBeqoyDWkVUjR1iyoKZfBcAfi8/Do8tM+lYluapY5dr6COa0yO52lxQgKKV
vFje1h1cLZW1/QcNpNvVBB+IPCZ5AkA/UyRBjLNwHAKXEW4iJy1T/1H5FGKBaIGB
4SS/f5QGzoX2bD0dmTAD3nABDjmqNgQUATeDENvYEQ3COF6IuKqBAkAxefuDjLbT
wtVE14AhMxnNt58HlOeNLUICipkq/cZBgkseHCurPEiXXVDARIA4nj82YTqKjXrp
mI/+1VLKBQ9Z
-----END PRIVATE KEY-----"""


def interleave(s: str) -> str:
    """密钥派生：偶数下标在前 + 奇数下标在后（= 安卓 getak 的交错）。"""
    return s[0::2] + s[1::2]


def rsa_encrypt(text: str) -> str:
    pub = RSA.import_key(PUBLIC_KEY_PEM)
    return base64.b64encode(PKCS1_v1_5.new(pub).encrypt(text.encode("utf-8"))).decode()


def rsa_decrypt_text(b64: str) -> str:
    priv = RSA.import_key(PRIVATE_KEY_PEM)
    sentinel = b"__FAIL__"
    raw = PKCS1_v1_5.new(priv).decrypt(base64.b64decode(b64), sentinel)
    if raw == sentinel:
        raise ValueError("RSA 解密失败")
    return raw.decode("utf-8")


def fetch_secrets():
    """调 getSecretKey，返回 (random, cpdailySecret, catSecret)。"""
    private_data = f"{uuid.uuid4()}|first_v4"
    payload = {
        "p": rsa_encrypt(private_data),
        "s": hashlib.md5(f"{private_data}&{SECRET_SALT}".encode("utf-8")).hexdigest(),
    }
    headers = {
        "Content-Type": "application/json",
        "CpdailyClientType": "CPDAILY",
        "CpdailyStandAlone": "0",
        "deviceType": "1",
        "clientType": "cpdaily_student",
        "User-Agent": "okhttp/4.12.0 cpdaily/9.9.24",
    }
    last = None
    for host in HOSTS:
        try:
            r = requests.post(host + SECRET_PATH, json=payload, headers=headers,
                              verify=False, timeout=20)
            if r.status_code != 200:
                last = f"{host} HTTP {r.status_code}"
                continue
            data = r.json()
            for _ in range(6):  # 兼容 data/datas/result 包裹
                if not isinstance(data, dict):
                    break
                for k in ("data", "datas", "result"):
                    if k in data:
                        data = data[k]
                        break
                else:
                    break
            if not isinstance(data, str) or not data:
                last = f"{host} 空数据"
                continue
            parts = rsa_decrypt_text(data).split("|")
            if len(parts) >= 3:
                return parts[0], parts[1], parts[2]
            last = f"{host} 段数不足"
        except Exception as e:
            last = f"{host} {type(e).__name__}: {e}"
    raise RuntimeError("getSecretKey 全部失败 -> " + str(last))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="不联网，直接打印已知固定 key")
    args = ap.parse_args()

    if args.offline:
        print("（离线）已知固定值：")
        print("  cpdailySecret =", KNOWN["cpdailySecret"])
        print("  catSecret     =", KNOWN["catSecret"])
        print("  fkey_cat      =", KNOWN["fkey_cat"], "  <- 签到 bodyString 的 AES key")
        print("  ckey_cpdaily  =", KNOWN["ckey_cpdaily"], "  <- 登录请求体的 AES key")
        return

    rnd, cpd, cat = fetch_secrets()
    fkey = interleave(LOCAL_PREFIX_FKEY + cat)
    ckey = interleave(LOCAL_PREFIX_CKEY + cpd)
    print("getSecretKey 协商结果：")
    print("  random        =", rnd)
    print("  cpdailySecret =", cpd)
    print("  catSecret     =", cat)
    print()
    print("派生密钥（interleave = 偶位+奇位交错）：")
    print("  fkey_cat      =", fkey, "  <- 签到 bodyString 的 AES key（16 字节）")
    print("  ckey_cpdaily  =", ckey, "  <- 登录请求体的 AES key（16 字节）")
    print()
    if fkey == KNOWN["fkey_cat"]:
        print("✅ 与已知固定值一致：fkey_cat =", KNOWN["fkey_cat"])


if __name__ == "__main__":
    main()
