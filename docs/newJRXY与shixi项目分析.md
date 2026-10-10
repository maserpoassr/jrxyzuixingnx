# 重大发现：`newJRXY-main` + `shixi-main` —— 缺口被补上了

> 分析日期：2026-10-06
> 结论：工作区里已有的两个项目，**合起来正好补齐我们卡住的那一环**（`appKey` / `getSecretKey`）。

---

## 0. TL;DR

| 项目 | 是什么 | 对我们的价值 |
|---|---|---|
| **`auto-cpdaily/newJRXY-main`** | JRXY-AutoSign-Reborn 的**新版分支**，实现了 **iOS 9.9.22 的 first_v4 签到协议** | 给出了**完整的提交协议**（headers + body + 密钥派生），并**证实**了我们的逆向结论 |
| **`shixi-main/今日校园`** | 另一个项目，实现了**原生 `getSecretKey` 动态密钥协商** | 给出了**我们唯一缺的那一步**：`getSecretKey` 接口 + **RSA 公/私钥** + 密钥派生 |

**两者合并 = 打通自动查寝所需的全部零件。**（但有一个风控前提，见第 5 节。）

---

## 1. `newJRXY-main` 是什么

它是 `TsangHaotian/JRXY-AutoSign-Reborn` 的**后继分支**（README 明确写了演化史），
定位是"**协议分析记录**"，实现了 iOS 客户端 9.9.22 的加密链路：

| 文件 | 作用 |
|---|---|
| `core.py` | 业务链路 + **iOS first_v4 加密/提交**实现 |
| `iap_login.py` | 网页版登录（RSA 密码加密 + 验证码 + 换票） |
| `app.py` / `main.py` / `run_once.py` | GUI / CLI 外壳 |
| `config.yml` | 配置（已脱敏为占位值） |

### 1.1 它证实的（与我们逆向**完全一致**）

| 项 | newJRXY 代码 | 我们的安卓逆向 |
|---|---|---|
| AES 算法 | `AES-128-CBC + PKCS7`（`aes_v4_encrypt`） | ✅ 一致 |
| AES IV | `bytes(range(1,10)) + bytes(range(1,8))` = `01020304050607080901020304050607` | ✅ 一致 |
| 密钥派生 | `final_cat_secret = (local + server_cat)[::2] + [1::2]`（**奇偶位交错**） | ✅ 我们的 `interleave("h8r7uN8t"+appKey)` 同一算法 |
| version | `first_v4` / `calVersion=firstv` | ✅ 一致 |
| 旧协议 | AES-ECB + 固定 key（`abcdfe0987612345`）"已不可用" | ✅ 与我们实测一致 |

> **结论：我们之前对安卓端的逆向 100% 正确。** 缺的从来不是算法，而是**服务端下发的密钥材料**。

### 1.2 它解释了我们遇到的"版本过低"

README 原文：
> "接口采用版本化路径，**算法版本字段取值必须与当前客户端一致，否则返回「请升级最新版本」**。"
> "响应体不是明文，而是 **RSA-1024 / PKCS1v15 密文**。解密后是管道符分隔的三段：随机串、`cpdailySecret`、`catSecret`。"

`core.py` 里的注释也印证：
> "`版本过低` —— 服务端解密失败的伪装报错。"

⇒ 我们之前用旧契约（AES-ECB/`abcdfe0987612345`）提交，服务端**解不出来**，于是伪装成"版本过低"。

### 1.3 它给出的完整提交协议（`_submit_ios_v4`）

**提交体**（`submit_data`）：
```json
{
  "lon": "<经度>", "lat": "<纬度>",
  "version": "first_v4", "calVersion": "firstv",
  "deviceId": "<设备ID>", "userId": "<学号>",
  "systemName": "iOS", "systemVersion": "18.2", "model": "iPhone 16 Pro",
  "appVersion": "9.9.22",
  "bodyString": "<AES-128-CBC-PKCS7(form JSON) → base64>",
  "sign": "<md5(排序后的form值 + bodyString + aes_key)>"
}
```

**请求头**（`headers`）：
```
deviceType: 2
CpdailyClientType: CPDAILY
sessionTokenKey: <sessionToken>
tenantId: <学校ID>
User-Agent: ... cpdaily/9.9.22 wisedu/9.9.22
CpdailyStandAlone: 0
Cookie: clientType=cpdaily_student; sessionToken=...; standAlone=0; tenantId=...; MOD_AUTH_CAS=...
```
> 注意：**iOS 协议没有 `Cpdaily-Extension` DES 头**，改用 Cookie 里的 `MOD_AUTH_CAS` + `sessionToken`。

### 1.4 它缺的那一块（被作者刻意排除）

`core.py` 里 `fetch_v4_secrets()` 依赖：
```python
from gsk_client import GskClient      # ← 来自 key_extract/ 目录
```
而 `key_extract/` **被 `.gitignore` 排除、不在仓库内**（README 也明说"不随仓库分发"）。
`IOS_LOCAL_CAT_SECRET` 也是空占位符。

⇒ **缺的正是"怎么调 `getSecretKey` 拿到 `catSecret`"这一步。**

---

## 2. `shixi-main` 是什么 —— 它把缺口补上了

`shixi-main/今日校园/今日校园.py` 实现了**原生短信登录**，但其中包含**我们缺的那一步**：

### 2.1 `getSecretKey` 协商（`negotiate_secret`）

```python
SECRET_PATH = "app/auth/dynamic/secret/getSecretKey/v-920"      # ← 接口路径!
SECRET_SALT = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"  # = sha256("hello")
LOCAL_SECRET_PREFIX = "f9akfyUe"                               # ← 我们逆向出的 getcKey!

private_data = f"{uuid.uuid4()}|first_v4"
payload = {
    "p": rsa_encrypt(private_data),                            # RSA-1024/PKCS1v15
    "s": md5(f"{private_data}&{SECRET_SALT}"),                 # MD5 签名
}
# POST {host}app/auth/dynamic/secret/getSecretKey/v-920
```

### 2.2 响应解密（`decrypt_service_secret`）

```python
parts = rsa_decrypt_text(value).split("|")     # RSA 私钥解密
# parts = [random_string, cpdailySecret_raw, catSecret]
cpdaily_secret = (LOCAL_SECRET_PREFIX + parts[1])[::2] + [1::2]   # ← 交错派生
cat_secret     = parts[2]
```

### 2.3 **RSA 公钥 + 私钥都在明文里**（`NATIVE_PUBLIC_KEY_PEM` / `NATIVE_PRIVATE_KEY_PEM`）

这正是 `newJRXY` 排除的"钥匙提取工具链"的产物！私钥以 PEM 明文内嵌。

### 2.4 与我们逆向的交叉验证

| shixi 里的值 | 我们安卓逆向出的值 | 结论 |
|---|---|---|
| `SECRET_SALT = 2cf24dba...` | `getSalt()` = `2cf24dba...` (=sha256("hello")) | ✅ 一致 |
| `LOCAL_SECRET_PREFIX = "f9akfyUe"` | `getcKey()` = `f9akfyUe` | ✅ 一致 |
| `AES_IV = (1..9,1..7)` | AES IV = `01..09 01..07` | ✅ 一致 |
| `DES_KEY = "XCE927=="` | 社区 DES key | ✅ 一致 |
| 派生 = 交错 | `getak` 交错 | ✅ 一致 |

⇒ **三个来源（安卓 native / newJRXY / shixi）完全对得上。** 证据链闭环。

---

## 3. 合并后能得到什么

把两块拼起来，就是一条**可能可用的完整链路**：

```
① 登录（已有：我们的 CAS 登录 ✅ / 或 shixi 的网页登录）
        ↓
② getSecretKey 协商（来自 shixi）
   POST app/auth/dynamic/secret/getSecretKey/v-920
   {p: RSA(uuid|first_v4), s: md5(uuid|first_v4 & sha256("hello"))}
        ↓  RSA 私钥解密 → random|cpdailySecret_raw|catSecret
③ 派生提交密钥（来自 newJRXY + 我们的安卓结论）
   aes_key = interleave(local_const + catSecret)
        ↓
④ 加密 bodyString = AES-128-CBC-PKCS7(form, aes_key, IV) → base64
        ↓
⑤ 按 iOS first_v4 格式提交（来自 newJRXY）
   POST .../submitSign  带 deviceType/sessionTokenKey/tenantId/Cookie(MOD_AUTH_CAS)
```

**唯一还需实测确认的点**：提交用的本地常量（`IOS_LOCAL_CAT_SECRET`）到底是
`h8r7uN8t`（安卓 submit 用的 getfKey）还是 `f9akfyUe`（shixi 登录用的 getcKey）。
这个可以**两种都试一次**即可确定。

---

## 4. 与之前路线的关系

| 路线 | 还需要什么 | 现在是否可做 |
|---|---|---|
| 安卓 Frida hook 拿 appKey | root 机 | 仍可用，但**已经没必要** |
| iOS 砸壳 + 抓包 | iPhone + 砸壳包 | 仍可用，但**大概率没必要了** |
| **合并 newJRXY + shixi（本方案）** | **只要账号 + 能跑 Python** | ✅ **最省事，推荐先试** |

因为 `getSecretKey` 的 RSA 私钥已经在 shixi 里明文给出，我们可以**直接用 Python 调用**
`getSecretKey` 拿 `catSecret`，**不需要任何设备、不需要抓包、不需要 hook**。

---

## 5. ⚠️ 必须知道的风险（newJRXY README 明确警告）

> "签到会触发设备验证风险。服务端会校验**账号与设备的绑定关系**，异常提交会被判定为
> 「**更换手机频繁 / 设备未授权**」，需**管理端人工授权**才能解除。这是有意设计的一道防线。"

- 提交时 `deviceId` 会随账号绑定；**每次用随机 deviceId 提交可能触发风控**；
- 触发后可能影响账号正常使用，需**找管理员解绑**；
- `newJRXY` 的未决问题里也写了："**设备指纹头的生成算法未复现** —— 这也正是风控难以逾越的根本原因。"

⇒ 建议：**用你本人真实手机的 deviceId**（可以从你手机抓一次包拿到），并且**谨慎、低频测试**。

---

## 6. 建议的下一步

1. **先静态核对**：把 newJRXY 的 `_submit_ios_v4` 与 shixi 的 `negotiate_secret` 拼成一份可运行的
   合并脚本（我可以直接写）；
2. **低频实测**：用你的真实账号 + 真实手机 deviceId，试一次提交；
3. 若 `版本过低` 消失 → 成功；若仍报错，再回到 iOS 砸壳/抓包定位差异。

---

## 7. 附：证据文件

| 文件 | 内容 |
|---|---|
| `auto-cpdaily/newJRXY-main/newJRXY-main/core.py` | iOS first_v4 提交协议（`_submit_ios_v4` / `final_cat_secret` / `aes_v4_encrypt`） |
| `auto-cpdaily/newJRXY-main/newJRXY-main/README.md` | 协议分析记录（含"版本过低"与风控说明） |
| `shixi-main/shixi-main/今日校园/今日校园.py` | `getSecretKey` 协商 + RSA 公/私钥 + 密钥派生 |
| `auto-cpdaily/_dex10.dex` | 安卓 DEX，含字符串 `app/auth/dynamic/secret/getSecretKey/v-920` |
