# -*- coding: utf-8 -*-
"""合并方案：CAS 登录 + getSecretKey 动态密钥 + iOS first_v4 提交。

把工作区两个项目的成果拼起来：
  - shixi-main         : getSecretKey 协商（RSA 公/私钥 + 密钥交错派生）
  - newJRXY-main       : iOS first_v4 提交协议（headers + bodyString + sign）
  - 本项目 actions/*    : 可用的 CAS 登录 + 查任务 + 组表单（含照片上传）

用法：
  # 只做“无副作用”探测：登录 + 领密钥 + 打印候选 key + 打印将要提交的 body（不提交）
  python scripts/merged_ios_v4_submit.py --dry

  # 真正提交（会消耗一次签到机会，注意风控）
  python scripts/merged_ios_v4_submit.py --submit

  # 指定密钥派生候选（默认自动按顺序试到成功）
  python scripts/merged_ios_v4_submit.py --submit --variant fkey_cat

⚠️ 风控提示：服务端会校验“账号↔设备”绑定。请用本人真实设备 deviceId，
   并尽量低频测试。触发“更换手机频繁/设备未授权”后需管理员解绑。
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
import uuid
import urllib.parse

import yaml
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.Padding import pad

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from actions.wiseLoginService import wiseLoginService
from actions.autoSign import AutoSign
from actions.utils import Utils

# ===========================================================================
# 1. 内置密钥材料（来自 shixi-main，明文内嵌）
# ===========================================================================
NATIVE_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCpwqE77zx+WexQWf1qDzb8EGey
et7VO78JiCDrZLcesaGjN5B8s66bMCfcn9R3GN25/EA3lFPI86hgluMPT6X1rneW
QRdKMaFWtxZLc+0Gdkf8zvdPf3rcYt6VjPnq3Hu1iSdytD8SIuTcSGFoPctId7jZ
zEjMjj74mnu3WtihZQIDAQAB
-----END PUBLIC KEY-----"""

NATIVE_PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
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

# ===========================================================================
# 2. 协议常量
# ===========================================================================
SECRET_PATH = "app/auth/dynamic/secret/getSecretKey/v-920"
SECRET_SALT = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"  # = sha256("hello")
LOCAL_PREFIX_FKEY = "h8r7uN8t"   # 安卓 getfKey（提交用）
LOCAL_PREFIX_CKEY = "f9akfyUe"   # 安卓 getcKey（登录用）
AES_IV = bytes((1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6, 7))
DES_KEY = b"XCE927=="
DES_IV = bytes(range(1, 9))

# getSecretKey 的主机候选（相对路径需要拼主机）
NATIVE_API_HOSTS = (
    "https://data-xxt.aichaoxing.com/",
    "https://mobile.campushoy.com/",
)

IOS_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) "
          "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 "
          "cpdaily/9.9.22 wisedu/9.9.22")
ANDROID_UA = ("Mozilla/5.0 (Linux; Android 14; 23127PN0CC Build/AP2A.240705.005; wv) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/120.0.6099.230 "
              "Mobile Safari/537.36 okhttp/4.12.0 cpdaily/9.9.22 wisedu/9.9.22")
IOS_APP_VERSION = "9.9.22"
IOS_SYSTEM_VERSION = "18.2"
IOS_MODEL = "iPhone 16 Pro"


# ===========================================================================
# 3. 加解密工具
# ===========================================================================
def interleave(s: str) -> str:
    """密钥派生：偶数位在前 + 奇数位在后（= 安卓 getak 交错）。"""
    return s[0::2] + s[1::2]


def aes_cbc_pkcs7_b64(data: bytes, key: bytes) -> str:
    return base64.b64encode(
        AES.new(key, AES.MODE_CBC, AES_IV).encrypt(pad(data, AES.block_size))
    ).decode()


def rsa_encrypt(text: str) -> str:
    pub = RSA.import_key(NATIVE_PUBLIC_KEY_PEM)
    return base64.b64encode(PKCS1_v1_5.new(pub).encrypt(text.encode("utf-8"))).decode()


def rsa_decrypt_text(b64: str) -> str:
    priv = RSA.import_key(NATIVE_PRIVATE_KEY_PEM)
    sentinel = os.urandom(32)
    plain = PKCS1_v1_5.new(priv).decrypt(base64.b64decode(b64), sentinel)
    if plain == sentinel:
        raise ValueError("RSA 解密失败（密钥不匹配）")
    return plain.decode("utf-8")


def des_b64(obj) -> str:
    payload = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(
        DES.new(DES_KEY, DES.MODE_CBC, DES_IV).encrypt(pad(payload, DES.block_size))
    ).decode()


# ===========================================================================
# 4. getSecretKey 协商
# ===========================================================================
class SecretError(Exception):
    pass


def fetch_secrets(session, tenant_id, device_id):
    """调用 getSecretKey，返回 (random_string, cpdaily_secret_raw, cat_secret)。"""
    private_data = f"{uuid.uuid4()}|first_v4"
    payload = {
        "p": rsa_encrypt(private_data),
        "s": hashlib.md5(f"{private_data}&{SECRET_SALT}".encode("utf-8")).hexdigest(),
    }
    initial_token = base64.b64encode(os.urandom(8)).decode()
    headers = {
        "Content-Type": "application/json",
        "CpdailyClientType": "CPDAILY",
        "CpdailyStandAlone": "0",
        "CpdailyInfo": des_b64({
            "deviceId": device_id, "systemName": "android",
            "appVersion": IOS_APP_VERSION, "model": "23127PN0CC",
            "lon": 0, "lat": 0, "cpdailyVersion": IOS_APP_VERSION,
            "systemVersion": "14", "userId": "",
        }),
        "tenantId": tenant_id,
        "clientType": "cpdaily_student",
        "deviceType": "1",
        "SessionTokenKey": initial_token,
        "SessionToken": initial_token,
        "wisDeviceId": device_id,
        "User-Agent": IOS_UA,
    }

    errors = []
    for host in NATIVE_API_HOSTS:
        url = host + SECRET_PATH
        try:
            r = session.post(url, json=payload, headers=headers,
                             verify=False, timeout=20)
            print(f"  [getSecretKey] {host} -> HTTP {r.status_code}")
            if r.status_code != 200:
                errors.append(f"{host}:HTTP{r.status_code}:{r.text[:120]}")
                continue
            try:
                body = r.json()
            except ValueError:
                errors.append(f"{host}:非JSON:{r.text[:120]}")
                continue
            # 兼容 data/datas/result 包裹
            data = body
            for _ in range(6):
                if not isinstance(data, dict):
                    break
                for k in ("data", "datas", "result"):
                    if k in data:
                        data = data[k]
                        break
                else:
                    break
            if not isinstance(data, str) or not data:
                errors.append(f"{host}:空数据:{json.dumps(body, ensure_ascii=False)[:150]}")
                continue
            plain = rsa_decrypt_text(data)
            parts = plain.split("|")
            if len(parts) < 3 or any(not p for p in parts[:3]):
                errors.append(f"{host}:段数不足:{plain[:120]}")
                continue
            return parts[0], parts[1], parts[2]
        except Exception as e:
            errors.append(f"{host}:{type(e).__name__}:{e}")
    raise SecretError("getSecretKey 全部失败 -> " + " | ".join(errors))


# ===========================================================================
# 5. 提交密钥候选
# ===========================================================================
def key_candidates(cpdaily_raw, cat):
    """返回 [(variant, aes_key, 说明)] —— 按可能性排序。"""
    return [
        ("fkey_cat", interleave(LOCAL_PREFIX_FKEY + cat), "interleave(h8r7uN8t + catSecret) [安卓提交用]"),
        ("ckey_cpdaily", interleave(LOCAL_PREFIX_CKEY + cpdaily_raw), "interleave(f9akfyUe + cpdailySecret) [shixi登录用]"),
        ("fkey_cpdaily", interleave(LOCAL_PREFIX_FKEY + cpdaily_raw), "interleave(h8r7uN8t + cpdailySecret)"),
        ("ckey_cat", interleave(LOCAL_PREFIX_CKEY + cat), "interleave(f9akfyUe + catSecret)"),
        ("cat_raw", cat, "catSecret 原值（不派生）"),
        ("cpdaily_raw", cpdaily_raw, "cpdailySecret 原值（不派生）"),
    ]


# ===========================================================================
# 6. iOS first_v4 提交
# ===========================================================================
def submit_ios_v4(session, host, api, form, aes_key, tenant_id, user_id,
                  device_id, session_token="", sign_mode="hash"):
    body_string = aes_cbc_pkcs7_b64(
        json.dumps(form, ensure_ascii=False).encode("utf-8"), aes_key.encode("utf-8"))
    if sign_mode == "hash":
        sign = Utils.md5("".join(sorted(str(v) for v in form.values())) + body_string + aes_key)
    elif sign_mode == "switch":
        sign = "1"
    else:
        sign = None

    submit_data = {
        "lon": form.get("longitude"), "lat": form.get("latitude"),
        "version": "first_v4", "calVersion": "firstv",
        "deviceId": device_id, "userId": user_id,
        "systemName": "iOS", "systemVersion": IOS_SYSTEM_VERSION,
        "model": IOS_MODEL, "appVersion": IOS_APP_VERSION,
        "bodyString": body_string,
    }
    if sign is not None:
        submit_data["sign"] = sign
    headers = {
        "deviceType": "2",
        "CpdailyClientType": "CPDAILY",
        "Accept": "*/*",
        "CacheTimeValue": "0",
        "sessionTokenKey": session_token,
        "Accept-Language": "zh-Hans-CN",
        "Content-Type": "application/json",
        "tenantId": tenant_id,
        "User-Agent": IOS_UA,
        "CpdailyStandAlone": "0",
    }
    cookie_parts = ["clientType=cpdaily_student", f"sessionToken={session_token}",
                    "standAlone=0", f"tenantId={tenant_id}"]
    for c in session.cookies:
        if c.name == "MOD_AUTH_CAS":
            cookie_parts.append(f"MOD_AUTH_CAS={c.value}")
    headers["Cookie"] = "; ".join(cookie_parts)

    return session.post(host + api, headers=headers,
                        data=json.dumps(submit_data, ensure_ascii=False),
                        verify=False, timeout=20)


def submit_android_v4(session, host, api, form, aes_key, tenant_id, user_id,
                      device_id, lon, lat, address, use_sign=True):
    """安卓原生 first_v4：Cpdaily-Extension(DES) 头 + AES-CBC bodyString + md5 sign。"""
    extension = {
        "lon": str(lon), "model": "23127PN0CC", "appVersion": IOS_APP_VERSION,
        "systemVersion": "14", "userId": "", "systemName": "android",
        "lat": str(lat), "deviceId": device_id,
    }
    body_string = aes_cbc_pkcs7_b64(
        json.dumps(form, ensure_ascii=False).encode("utf-8"), aes_key.encode("utf-8"))

    form_data = {
        "version": "first_v4", "calVersion": "firstv",
        "bodyString": body_string,
    }
    if use_sign:
        import urllib.parse
        sign_form = dict(form)
        sign_form["bodyString"] = body_string
        form_data["sign"] = Utils.md5(
            urllib.parse.urlencode(sign_form) + "&" + aes_key)
    form_data.update(extension)

    des_key = "b3L26XNL"
    headers = {
        "User-Agent": ANDROID_UA,
        "CpdailyStandAlone": "0",
        "extension": "1",
        "Cpdaily-Extension": Utils.DESEncrypt(json.dumps(extension), des_key),
        "Content-Type": "application/json; charset=utf-8",
        "Host": re.findall("//(.*?)/", host)[0],
        "Connection": "Keep-Alive",
    }
    return session.post(host + api, headers=headers,
                        data=json.dumps(form_data, ensure_ascii=False),
                        verify=False, timeout=20)


def submit_app_native(session, host, api, form, aes_key, tenant_id, user_id,
                      device_id, lon, lat, session_token="",
                      app_version=IOS_APP_VERSION, system_version="14",
                      model="23127PN0CC", include_info=True, include_ext=True):
    """完全复刻安卓原生 App 的提交（ServiceHelper 拦截器 + UIViewPlugin.sendEncryptPostRequest）。

    头：
      sessionTokenKey/SessionToken = DES(sessionToken, "XCE927==")
      CpdailyInfo   = DES(deviceJSON, "ST83=@XV")   （cp7.a）
      Cpdaily-Extension = DES(deviceJSON, "b3L26XNL")（cp7.b）
      deviceType=1, CpdailyClientType=CPDAILY, clientType=cpdaily_student
    体：
      {systemName,systemVersion,model,deviceId,appVersion,lon,lat,userId,bodyString,version,calVersion}
    """
    body_string = aes_cbc_pkcs7_b64(
        json.dumps(form, ensure_ascii=False).encode("utf-8"), aes_key.encode("utf-8"))

    device_info = {
        "systemName": "android", "systemVersion": str(system_version),
        "model": model, "deviceId": device_id, "appVersion": app_version,
        "lon": float(lon), "lat": float(lat), "userId": user_id,
    }
    device_json = json.dumps(device_info, ensure_ascii=False)

    body = dict(device_info)
    body["bodyString"] = body_string
    body["version"] = "first_v4"
    body["calVersion"] = "firstv"

    def des(s, key):
        if s is None or s == "":
            return ""
        return Utils.DESEncrypt(s, key)

    headers = {
        "tenantId": tenant_id,
        "User-Agent": ANDROID_UA,
        "CpdailyStandAlone": "0",
        "extension": "1",
        "sign": "1",
        "CpdailyClientType": "CPDAILY",
        "clientType": "cpdaily_student",
        "deviceType": "1",
        "Content-Type": "application/json; charset=utf-8",
        "Host": re.findall("//(.*?)/", host)[0],
        "Connection": "Keep-Alive",
    }
    if session_token:
        tok = des(session_token, "XCE927==")
        headers["sessionTokenKey"] = tok
        headers["SessionToken"] = tok
    if include_ext:
        headers["Cpdaily-Extension"] = des(device_json, "b3L26XNL")
    if include_info:
        headers["CpdailyInfo"] = des(device_json, "ST83=@XV")

    return session.post(host + api, headers=headers,
                        data=json.dumps(body, ensure_ascii=False),
                        verify=False, timeout=20)


# ===========================================================================
# 7. 主流程
# ===========================================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry", action="store_true", help="只探测不提交（默认行为）")
    ap.add_argument("--submit", action="store_true", help="真正提交签到（否则只 dry-run）")
    ap.add_argument("--variant", default=None, help="指定密钥候选，如 fkey_cat")
    ap.add_argument("--max-tries", type=int, default=3, help="最多尝试几个密钥候选（默认3）")
    ap.add_argument("--device-id", default=None, help="固定 deviceId（建议填本人真机）")
    ap.add_argument("--model", default=None, help="覆盖设备型号（app 协议），如 CPDAILY")
    ap.add_argument("--sysver", default=None, help="覆盖系统版本（app 协议），如 13")
    ap.add_argument("--lon", type=float, default=None, help="覆盖经度")
    ap.add_argument("--lat", type=float, default=None, help="覆盖纬度")
    ap.add_argument("--address", default=None, help="覆盖定位地址文本")
    ap.add_argument("--protocol", choices=["ios", "android", "app"], default="ios",
                    help="提交协议：ios(iOS first_v4) / android(安卓旧) / app(安卓原生全头)")
    ap.add_argument("--no-info", action="store_true", help="app 协议：不发送 CpdailyInfo 头")
    ap.add_argument("--no-ext", action="store_true", help="app 协议：不发送 Cpdaily-Extension 头")
    ap.add_argument("--sign-mode", choices=["hash", "switch", "none"], default="hash",
                    help="sign 字段：hash(md5) / switch(=1) / none(不带)")
    ap.add_argument("--userid", default=None, help="覆盖提交体 userId（默认=学号；可传空串）")
    args = ap.parse_args()

    conf = yaml.safe_load(open(os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "config.yml"), encoding="utf-8"))
    user = conf["users"][0]["user"]
    if args.lon is not None:
        user["lon"] = args.lon
    if args.lat is not None:
        user["lat"] = args.lat
    if args.address is not None:
        user["address"] = args.address

    print("=" * 60)
    print("步骤 1/5  CAS 登录")
    print("=" * 60)
    wise = wiseLoginService(user, user.get("httpProxy", ""))
    wise.getLoginUrlBySchoolName()
    print("campus_host =", wise.campus_host)
    wise.login()
    print("登录成功，cookies =", [c.name for c in wise.session.cookies])

    # ★ sessionToken：campus 门户在 CAS 的 service 参数里下发（app 登录换票同源）。
    session_token = ""
    try:
        q = urllib.parse.parse_qs(urllib.parse.urlparse(wise.login_url).query)
        svc = q.get("service", [""])[0]
        session_token = urllib.parse.parse_qs(
            urllib.parse.urlparse(svc).query).get("sessionToken", [""])[0]
    except Exception:
        pass
    if not session_token:
        for c in wise.session.cookies:
            if c.name == "sessionToken":
                session_token = c.value
    print("sessionToken =", session_token or "(空)")

    # tenantId
    schools = wise.session.get(
        "https://mobile.campushoy.com/v6/config/guest/tenant/list",
        verify=False).json()["data"]
    tenant_id = next((s["id"] for s in schools if s["name"] == user["schoolName"]), "")
    print("tenantId =", tenant_id)

    # deviceId：服务端按“账号↔设备”绑定，必须固定（随机=更换手机频繁→风控）。
    did_file = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), ".device_id")
    if args.device_id:
        device_id = args.device_id
    elif os.path.exists(did_file):
        device_id = open(did_file, encoding="utf-8").read().strip()
    else:
        # App 用 UUID.randomUUID().toString()（Java 输出为小写带连字符），此处保持一致
        device_id = str(uuid.uuid4())
        open(did_file, "w", encoding="utf-8").write(device_id)
    print("deviceId =", device_id, "(已固定，保存在 .device_id)")

    print()
    print("=" * 60)
    print("步骤 2/5  查任务 + 组表单（含照片上传）")
    print("=" * 60)
    sign = AutoSign(wise, user)
    sign.getUnSignTask()
    print("任务:", sign.taskInfo)
    sign.getDetailTask()
    print("详情: isPhoto=%s isNeedExtra=%s" % (sign.task.get("isPhoto"), sign.task.get("isNeedExtra")))
    sign.fillForm()
    print("表单字段:", json.dumps(sign.form, ensure_ascii=False)[:400])

    print()
    print("=" * 60)
    print("步骤 3/5  getSecretKey 动态密钥协商")
    print("=" * 60)
    cpdaily_raw, cat = None, None
    try:
        rnd, cpdaily_raw, cat = fetch_secrets(wise.session, tenant_id, device_id)
        print("✅ 领取成功")
        print("  random        =", rnd)
        print("  cpdailySecret =", cpdaily_raw)
        print("  catSecret     =", cat)
    except SecretError as e:
        print("❌ 领取失败:", e)
        print("   -> getSecretKey 主机/会话不匹配，需换 host 或带正确 SessionToken。")
        sys.exit(2)

    cands = key_candidates(cpdaily_raw, cat)
    print("\n候选 AES 提交密钥：")
    for name, key, desc in cands:
        print("  [%s] key=%s  (%s)" % (name, key, desc))

    print()
    print("=" * 60)
    print("步骤 4/5  构造 bodyString（不提交）")
    print("=" * 60)
    probe_key = cands[0][1].encode("utf-8")
    body_string = aes_cbc_pkcs7_b64(
        json.dumps(sign.form, ensure_ascii=False).encode("utf-8"), probe_key)
    print("bodyString(前120) =", body_string[:120])

    if not args.submit:
        print()
        print("== DRY RUN 结束（未提交）。确认无误后加 --submit 真正提交。==")
        return

    print()
    print("=" * 60)
    print("步骤 5/5  iOS first_v4 提交")
    print("=" * 60)
    uid = user["username"] if args.userid is None else args.userid

    to_try = cands if not args.variant else [c for c in cands if c[0] == args.variant]
    if not to_try:
        print("未知 variant:", args.variant)
        sys.exit(2)
    to_try = to_try[:max(1, args.max_tries)]

    for name, key, desc in to_try:
        print("\n--- 尝试候选 [%s] %s ---" % (name, desc))
        try:
            if args.protocol == "app":
                resp = submit_app_native(wise.session, wise.campus_host, sign.apis[2],
                                         sign.form, key, tenant_id, uid,
                                         device_id, user["lon"], user["lat"],
                                         session_token,
                                         app_version=IOS_APP_VERSION,
                                         system_version=(args.sysver or "14"),
                                         model=(args.model or "23127PN0CC"),
                                         include_info=not args.no_info,
                                         include_ext=not args.no_ext)
            elif args.protocol == "android":
                resp = submit_android_v4(wise.session, wise.campus_host, sign.apis[2],
                                         sign.form, key, tenant_id, uid,
                                         device_id, user["lon"], user["lat"], user["address"],
                                         use_sign=(args.sign_mode == "hash"))
            else:
                resp = submit_ios_v4(wise.session, wise.campus_host, sign.apis[2],
                                     sign.form, key, tenant_id, uid,
                                     device_id, session_token, args.sign_mode)
        except Exception as e:
            print("请求异常:", e)
            continue
        print("HTTP", resp.status_code)
        print("响应:", resp.text[:400])
        if "版本过低" in resp.text:
            print("=> 仍报版本过低（key 不对），继续下一个候选")
            time.sleep(1.5)
            continue
        print("=> 响应不是“版本过低”，key 可能正确！")
        try:
            j = resp.json()
            if j.get("message") == "SUCCESS":
                print("🎉🎉 签到成功！")
                return
            print("服务端消息:", j.get("message"))
        except Exception:
            pass
        # 非版本过低即视为找到正确 key，停止继续
        return


if __name__ == "__main__":
    main()
