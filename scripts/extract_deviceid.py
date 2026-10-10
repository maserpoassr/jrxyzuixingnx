# -*- coding: utf-8 -*-
"""从抓包得到的 CpdailyInfo / Cpdaily-Extension 头解出真实 deviceId。

用法：
  python scripts/extract_deviceid.py "<CpdailyInfo 头的值>"
  python scripts/extract_deviceid.py --ext "<Cpdaily-Extension 头的值>"
  python scripts/extract_deviceid.py --hex "<...>"      # 若抓到的是 hex 而非 base64

原理（反编译自 classes10.dex / classes8.dex）：
  CpdailyInfo      = base64( DES-CBC-PKCS5(deviceJSON, key="ST83=@XV") )   cp7.a()
  Cpdaily-Extension= base64( DES-CBC-PKCS5(deviceJSON, key="b3L26XNL") )   cp7.b()
  DES IV = 01 02 03 04 05 06 07 08
  deviceJSON = {systemName, systemVersion, model, deviceId, appVersion, lon, lat, userId}
"""
import argparse
import base64
import json
import sys

from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad

IV = bytes(range(1, 9))
KEYS = {"info": b"ST83=@XV", "ext": b"b3L26XNL", "token": b"XCE927=="}


def dec(value: str, key: bytes) -> str:
    raw = base64.b64decode(value)
    pt = DES.new(key, DES.MODE_CBC, IV).decrypt(raw)
    try:
        pt = unpad(pt, DES.block_size)
    except Exception:
        pass
    return pt.decode("utf-8", errors="replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("value", nargs="?", help="头的值（base64）")
    ap.add_argument("--ext", action="store_true", help="按 Cpdaily-Extension(b3L26XNL) 解")
    ap.add_argument("--token", action="store_true", help="按 sessionToken(XCE927==) 解")
    ap.add_argument("--hex", action="store_true", help="输入是 hex 而不是 base64")
    args = ap.parse_args()

    if not args.value:
        print(__doc__)
        sys.exit(1)

    val = args.value.strip()
    if args.hex:
        val = base64.b64encode(bytes.fromhex(val.replace(" ", ""))).decode()

    key = KEYS["ext"] if args.ext else KEYS["token"] if args.token else KEYS["info"]
    tag = "Cpdaily-Extension" if args.ext else "sessionToken" if args.token else "CpdailyInfo"

    try:
        plain = dec(val, key)
    except Exception as e:
        print("解密失败:", e)
        print("提示：确认是 %s 头；若是 hex 请加 --hex" % tag)
        sys.exit(2)

    print("== %s 解密结果 ==" % tag)
    print(plain)
    try:
        obj = json.loads(plain)
        print("\n== 解析 ==")
        for k, v in obj.items():
            print("  %-14s = %s" % (k, v))
        if "deviceId" in obj:
            print("\n>>> 真实 deviceId = %s" % obj["deviceId"])
            print("    用法: python scripts/merged_ios_v4_submit.py --submit "
                  "--variant fkey_cat --protocol app --device-id \"%s\"" % obj["deviceId"])
    except Exception:
        pass


if __name__ == "__main__":
    main()
