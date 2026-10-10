# 今日校园（CPDaily / Campusphere）签到请求加密 · 逆向与复现

> 本仓库是对「今日校园」App 签到/查寝提交接口**请求加密**的逆向复现，核心解决一件事：
> **打卡时提示「今日校园版本过低」** —— 因为新版 App 的请求体加密密钥变了。

- 目标版本：CPDaily App **9.9.x**（分析样本 9.9.24）
- 语言：Python 3.7+
- 免责声明：仅供**学习交流 / 安全研究**，禁止商业用途。虚拟定位、代签到可能违反校规与平台条款，请自行确认合规。

---

## ★ 核心：签到 AES 密钥 `fkey_cat` 的获取与解密方法

### 1. 问题现象

老脚本/老工具提交签到会返回：

```json
{"code":"4","message":"今日校园版本过低"}
```

**这不是真的版本问题**，而是**服务端解不开你的请求体**（加密密钥不对）时返回的伪装报错。

### 2. 加密协议（新版）

提交体 `bodyString` 的加密方式：

```
bodyString = base64( AES-128-CBC-PKCS7( json(表单), key = fkey_cat ) )

IV  = 01 02 03 04 05 06 07 08 09 01 02 03 04 05 06 07
key = fkey_cat（16 字节 ASCII 字符串）
```

- 旧协议用的是**固定 key `abcdfe0987612345` + AES-ECB**（已废弃，会报"版本过低"）。
- 新版改为**由 `getSecretKey` 接口协商出的密钥** `fkey_cat`。

### 3. 密钥 `fkey_cat` 的通用获取方法

调用接口 `POST https://mobile.campushoy.com/app/auth/dynamic/secret/getSecretKey/v-920`
（**无需登录**）：

```jsonc
// 请求体
{
  "p": RSA_PKCS1v15( "<uuid4>|first_v4" ),
  "s": md5( "<uuid4>|first_v4&2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" )
}
// 响应 data 为 RSA 加密串，用内置私钥解密后得到：
//   "<random>|<cpdailySecret>|<catSecret>"
```

派生（`interleave(s) = s[0::2] + s[1::2]`，即偶位在前、奇位在后）：

```
fkey_cat     = interleave("h8r7uN8t" + catSecret)      # 签到 bodyString 用
ckey_cpdaily = interleave("f9akfyUe" + cpdailySecret)  # 登录请求体用
```

**一条命令拿到密钥：**

```bash
pip install requests pycryptodome
python scripts/get_fkey_cat.py
```

> ⚠️ **实测结论**：`cpdailySecret / catSecret` 在**不同设备、不同学校、不同账号**下**完全相同**，
> 即密钥实为**全平台固定值**：
>
> ```
> catSecret = 9hriwfra
> fkey_cat  = hru89rwr87Nthifa        ← 签到 AES key（本仓库核心）
> ckey_cpdaily = fafUY9659kyengTR     ← 登录 AES key
> ```
>
> 所以你可以**直接硬编码** `hru89rwr87Nthifa`；`get_fkey_cat.py` 提供的是**接口获取方法**，
> 以便服务端将来轮换密钥时仍可用。

### 4. 解密 / 加密方法

```bash
python scripts/aes_body.py encrypt '{"signInstanceWid":"123"}'   # -> bodyString
python scripts/aes_body.py decrypt '<bodyString>'                # -> 明文 JSON
python scripts/aes_body.py demo                                  # 自测
```

或直接用 `scripts/aes_body.py` 里的 `encrypt_body / decrypt_body` 两个函数。

### 5. 一句话修复"版本过低"

> **把提交体加密从「`abcdfe0987612345` + AES-ECB」改成「`hru89rwr87Nthifa` + AES-CBC-PKCS7（IV=0102..09 0102..07）」即可。**

---

## 完整请求契约（安卓原生）

**请求头**（每个请求都带）：

| 头 | 生成方式 |
|---|---|
| `tenantId` | 学校租户 id |
| `CpdailyClientType` / `clientType` / `deviceType` | `CPDAILY` / `cpdaily_student` / `1` |
| `CpdailyStandAlone` / `extension` / `sign` | `0` / `1` / `1` |
| `sessionTokenKey` / `SessionToken` | `DES(sessionToken, "XCE927==")` |
| `CpdailyInfo` | `DES(deviceJSON, "ST83=@XV")` |
| `Cpdaily-Extension` | `DES(deviceJSON, "b3L26XNL")` |

- DES = `DES/CBC/PKCS5Padding`，IV = `0102030405060708`，输出 base64。
- `deviceJSON = {systemName, systemVersion, model, deviceId, appVersion, lon, lat, userId}`
- `deviceId` = App 首启生成的随机 UUID（落盘持久化，**非** OAID/IMEI）。

**请求体**：

```jsonc
{
  "systemName":"android","systemVersion":"...","model":"...","deviceId":"...",
  "appVersion":"9.9.24","lon":0.0,"lat":0.0,"userId":"...",
  "bodyString":"<AES(json(表单), fkey_cat) 的 base64>",
  "version":"first_v4", "calVersion":"firstv"
}
```

**关键接口**（host = `https://mobile.campushoy.com`）：

| 功能 | 方法 | 路径 |
|---|---|---|
| 取密钥 | POST | `/app/auth/dynamic/secret/getSecretKey/v-920` |
| 查任务 | POST | `<campus_host>wec-counselor-attendance-apps/student/attendance/getStuAttendacesInOneDay` |
| 任务详情 | POST | `<campus_host>wec-counselor-attendance-apps/student/attendance/detailSignInstance` |
| 提交签到 | POST | `<campus_host>wec-counselor-attendance-apps/student/attendance/submitSign` |

---

## 仓库结构

```
.
├── README.md                     # 本文件（★ 密钥获取 + 解密方法）
├── config.example.yml            # 配置模板（复制为 config.yml 后填写）
├── requirements.txt
├── docs/
│   ├── 请求加密接口_逆向分析.md    # 完整技术报告（含每步证据、密钥验证）
│   └── newJRXY与shixi项目分析.md   # 密钥来源交叉验证
├── scripts/
│   ├── get_fkey_cat.py           # ★ 获取/派生 fkey_cat（免登录）
│   ├── aes_body.py               # ★ bodyString 加解密
│   ├── merged_ios_v4_submit.py   # 完整签到脚本（登录→查任务→上传照片→加密→提交）
│   ├── extract_deviceid.py       # 解密 CpdailyInfo 头，取真实 deviceId
│   └── dryrun_query_tasks.py     # 只登录+查任务（无副作用）
└── actions/                      # 依赖模块（登录 / 组表单 / 上传 / 提交）
```

## 快速开始

```bash
pip install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple

# 1) 取密钥（免登录）
python scripts/get_fkey_cat.py

# 2) 加解密自测
python scripts/aes_body.py demo

# 3) 复制配置并填写（学号/密码/定位）
cp config.example.yml config.yml

# 4) 只查任务（无副作用）
python scripts/dryrun_query_tasks.py

# 5) 提交（会真实签到，注意风控）
python scripts/merged_ios_v4_submit.py --submit --variant fkey_cat --protocol app
```

`merged_ios_v4_submit.py` 参数：`--dry`（默认，只探测）/ `--submit` / `--variant` /
`--protocol {ios,android,app}` / `--device-id` / `--model` / `--sysver` / `--lon` / `--lat` / `--address`。

---

## 重要提醒（风控）

- 服务端会校验**「账号 ↔ 设备」绑定**：**频繁更换 `deviceId` 会触发**
  `{"code":"3","message":"您疑似更换手机频繁，…请联系辅导员在辅导猫的手机授权管理功能中为您授权…"}`。
  → **请固定一个 deviceId，切勿反复更换**（这是踩坑最多的点）。
- 定位**必须落在服务端签到点的半径内**，否则返回 `{"code":"2210990000","message":"签到失败"}`。
- 任务校验（`code:5 任务实例不存在`）**先于**设备校验（`code:3`）；窗口外/无任务时无法测试。

---

## 许可

沿用上游 `auto-cpdaily` 的 **MPL-2.0** 许可（见 `LICENSE`）。
