"""公共工具 Utils：配置/日志/加密/验证码/上传/提交/请求头。"""
import base64
import json
import random
import requests
import rsa
import sys
import yaml
from io import BytesIO
from Crypto.Cipher import AES
from tencentcloud.common import credential
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.ocr.v20181119 import ocr_client, models
from datetime import datetime, timedelta, timezone
from requests_toolbelt import MultipartEncoder
import os
from pyDes import des, CBC, PAD_PKCS5
import re
import uuid
import hashlib
import urllib.parse


class Utils:
    def __init__(self):
        pass

    # ddddocr 本地识别实例缓存（懒加载，全局共享）。
    _ddddocr_instance = None

    # 获取指定长度的随机字符
    @staticmethod
    # 生成指定长度随机串（登录密码加盐用）。
    def randString(length):
        baseString = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
        data = ''
        for i in range(length):
            data += baseString[random.randint(0, len(baseString) - 1)]
        return data

    @staticmethod
    # 读取 config.yml 并注入 Version。
    def getYmlConfig(yaml_file=os.path.join(os.path.dirname(__file__),
                                            '../config.yml')):
        file = open(yaml_file, 'r', encoding="utf-8")
        file_data = file.read()
        file.close()
        config = dict(yaml.load(file_data, Loader=yaml.FullLoader))
        config['Version'] = '1.9.0'
        return config

    # aes加密的实现
    @staticmethod
    # AES-CBC 加密（老登录/旧接口，固定iv）。
    def encryptAES(data, key):
        ivStr = '\x01\x02\x03\x04\x05\x06\x07\x08\x09\x01\x02\x03\x04\x05\x06\x07'
        aes = AES.new(bytes(key, encoding='utf-8'), AES.MODE_CBC,
                      bytes(ivStr, encoding="utf8"))
        text_length = len(data)
        amount_to_pad = AES.block_size - (text_length % AES.block_size)
        if amount_to_pad == 0:
            amount_to_pad = AES.block_size
        pad = chr(amount_to_pad)
        data = data + pad * amount_to_pad
        text = aes.encrypt(bytes(data, encoding='utf-8'))
        text = base64.encodebytes(text)
        text = text.decode('utf-8').strip()
        return text

    # AES-ECB/PKCS7 加密（今日校园 9.9.11+ 提交 body 专用，无 IV）。
    # key 默认使用社区 Frida 验证可用值 abcdfe0987612345（与 JRXY-AutoSign-Reborn 一致）。
    # 如需测试其他 key，直接传参覆盖即可，切勿再破坏本方法的 @staticmethod 结构。
    @staticmethod
    def encryptAES_ECB(data, key='abcdfe0987612345'):
        aes = AES.new(bytes(key, encoding='utf-8'), AES.MODE_ECB)
        text_length = len(data)
        amount_to_pad = AES.block_size - (text_length % AES.block_size)
        if amount_to_pad == 0:
            amount_to_pad = AES.block_size
        pad = chr(amount_to_pad)
        data = data + pad * amount_to_pad
        text = aes.encrypt(bytes(data, encoding='utf-8'))
        return base64.b64encode(text).decode()

    # 通过url解析图片验证码
    @staticmethod
    # 本地ddddocr优先识别图片验证码，失败回退腾讯云OCR。
    def getCodeFromImg(res, imgUrl, retry=10):
        if retry <= 0:
            raise Exception('验证码识别重试超限，请检查验证码配置')
        Utils.log('开始识别验证码')
        response = res.get(imgUrl, verify=False)  # 将这个图片保存在内存
        # 优先使用 ddddocr 本地识别（无需腾讯云密钥）
        try:
            import ddddocr
            if Utils._ddddocr_instance is None:
                Utils.log('初始化ddddocr本地识别')
                Utils._ddddocr_instance = ddddocr.DdddOcr(show_ad=False)
            code = str(Utils._ddddocr_instance.classification(
                response.content)).strip().replace(' ', '')
            if len(code) > 3:
                Utils.log('识别验证码成功')
                return code
            Utils.log('识别结果不正确正在重试')
            return Utils.getCodeFromImg(res, imgUrl, retry - 1)
        except ImportError:
            pass  # 未安装ddddocr时回退腾讯云OCR
        except Exception as err:
            Utils.log('本地识别异常:' + str(err) + '，正在重试')
            return Utils.getCodeFromImg(res, imgUrl, retry - 1)
        # 回退：腾讯云 OCR（需在config.yml配置ocrOption密钥）
        # 得到这个图片的base64编码
        imgCode = str(base64.b64encode(BytesIO(response.content).read()),
                      encoding='utf-8')
        # print(imgCode)
        try:
            cred = credential.Credential(
                Utils.getYmlConfig()['ocrOption']['SecretId'],
                Utils.getYmlConfig()['ocrOption']['SecretKey'])
            httpProfile = HttpProfile()
            httpProfile.endpoint = "ocr.tencentcloudapi.com"

            clientProfile = ClientProfile()
            clientProfile.httpProfile = httpProfile
            client = ocr_client.OcrClient(cred, "ap-beijing", clientProfile)

            req = models.GeneralBasicOCRRequest()
            params = {"ImageBase64": imgCode}
            req.from_json_string(json.dumps(params))
            resp = client.GeneralBasicOCR(req)
            codeArray = json.loads(resp.to_json_string())['TextDetections']
            code = ''
            for item in codeArray:
                code += item['DetectedText'].replace(' ', '')
            if len(code) > 3:
                Utils.log('识别验证码成功')
                return code
            else:
                Utils.log('识别结果不正确正在重试')
                return Utils.getCodeFromImg(res, imgUrl, retry - 1)
        except TencentCloudSDKException as err:
            raise Exception('验证码识别出现问题了' + str(err.message))

    @staticmethod
    # RSA 加密（CAS pwdDefaultEncryptSalt分支）。
    def encryptRSA(message, m, e):
        mm = int(m, 16)
        ee = int(e, 16)
        rsa_pubkey = rsa.PublicKey(mm, ee)
        crypto = Utils._encrypt_rsa(message.encode(), rsa_pubkey)
        return crypto.hex()

    @staticmethod
    def _pad_for_encryption_rsa(message, target_length):
        message = message[::-1]
        max_msglength = target_length - 11
        msglength = len(message)
        padding = b''
        padding_length = target_length - msglength - 3
        for i in range(padding_length):
            padding += b'\x00'
        return b''.join([b'\x00\x00', padding, b'\x00', message])

    @staticmethod
    def _encrypt_rsa(message, pub_key):
        keylength = rsa.common.byte_size(pub_key.n)
        padded = Utils._pad_for_encryption_rsa(message, keylength)
        payload = rsa.transform.bytes2int(padded)
        encrypted = rsa.core.encrypt_int(payload, pub_key.e, pub_key.n)
        block = rsa.transform.int2bytes(encrypted, keylength)
        return block

    @staticmethod
    # 打印带北京时间+版本号的日志。
    def log(content):
        print(Utils.getTimeStr() + " V%s %s" %
              (Utils.getYmlConfig()['Version'], content))
        sys.stdout.flush()

    @staticmethod
    # 返回东八区当前时间字符串。
    def getTimeStr():
        utc_dt = datetime.utcnow().replace(tzinfo=timezone.utc)
        bj_dt = utc_dt.astimezone(timezone(timedelta(hours=8)))
        return bj_dt.strftime("%Y-%m-%d %H:%M:%S")

    # 上传图片到对象存储(兼容腾讯云COS/阿里云OSS)
    @staticmethod
    # 拿上传凭证并直传对象存储（COS优先/OSS回退，失败走代理重试）。
    def uploadPicture(env, api, picSrc):
        url = env.host + api
        res = env.session.post(url=url,
                               headers={'content-type': 'application/json'},
                               data=json.dumps({'fileType': 1}),
                               verify=False)
        datas = res.json().get('datas')
        fileName = datas.get('fileName')+".jpg"
        policy = datas.get('policy')
        accessKeyId = datas.get('accessid')
        signature = datas.get('signature')
        policyHost = datas.get('host')
        headers = {
            'User-Agent':
            'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0'
        }
        file_path = os.path.join(os.path.dirname(__file__), '../', picSrc)
        # 优先使用服务端返回的 formData(腾讯云COS签名表单)，否则回退到阿里云OSS字段
        formData = datas.get('formData')
        if formData:
            fields = dict(formData)
            fields['file'] = ('blob', open(file_path, 'rb'), 'image/jpg')
        else:
            fields = {
                'key': fileName, 'policy': policy, 'AccessKeyId': accessKeyId,
                'signature': signature, 'x-obs-acl': 'public-read',
                'file': ('blob', open(file_path, 'rb'), 'image/jpg')
            }
        multipart_encoder = MultipartEncoder(fields=fields)
        headers['Content-Type'] = multipart_encoder.content_type
        # OSS 上传：先直连，失败再走系统代理；并做多重试规避偶发 SSL EOF / 断连
        sys_proxies = requests.utils.getproxies() or None
        last_err = None
        for proxies in ([None, ] + ([sys_proxies] if sys_proxies else [])):
            for _ in range(2):
                try:
                    env.session.post(url=policyHost,
                                     headers=headers,
                                     data=multipart_encoder,
                                     proxies=proxies,
                                     verify=False,
                                     timeout=60)
                    return fileName
                except Exception as e:
                    last_err = e
                    continue
        raise last_err
        return fileName

    # 获取图片上传位置
    @staticmethod
    # 按ossKey换正式图片URL。
    def getPictureUrl(env, api, fileName):
        url = env.host + api
        params = {'ossKey': fileName}
        res = env.session.post(url=url,
                               headers={'content-type': 'application/json'},
                               data=json.dumps(params),
                               verify=False)
        photoUrl = res.json().get('datas')
        return photoUrl

    # 利用hook判断当前返回的状态码是否正常
    @staticmethod
    # response hook：418抛IP被封禁。
    def checkStatus(request, *args, **kwargs):
        if request.status_code == 418:
            raise Exception('418错误,当前IP地址已被今日校园封禁')

    @staticmethod
    # DES-CBC 加密（请求头/签名用）。
    def DESEncrypt(s, key='XCE927=='):
        key = key
        iv = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        k = des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
        encrypt_str = k.encrypt(s)
        return base64.b64encode(encrypt_str).decode()

    @staticmethod
    # MD5 hex。
    def md5(str):
        md5 = hashlib.md5()
        md5.update(str.encode("utf8"))
        return md5.hexdigest()

    @staticmethod
    # 统一加密提交：bodyString ECB加密+MD5签名后POST。
    def submitFormData(env):
        extension = {
            "lon": env.userInfo['lon'],
            "model": "23127PN0CC",
            "appVersion": "9.9.22",
            "systemVersion": "14",
            "userId": '',
            "systemName": "android",
            "lat": env.userInfo['lat'],
            "deviceId": str(uuid.uuid1())
        }
        headers = {
            'User-Agent':
            'Mozilla/5.0 (Linux; Android 14; 23127PN0CC Build/AP2A.240705.005; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/120.0.6099.230 Mobile Safari/537.36 okhttp/4.12.0 cpdaily/9.9.22 wisedu/9.9.22',
            'CpdailyStandAlone': '0',
            'extension': '1',
            'Cpdaily-Extension': Utils.DESEncrypt(json.dumps(extension)),
            'Content-Type': 'application/json; charset=utf-8',
            'Accept-Encoding': 'gzip',
            'Host': re.findall('//(.*?)/', env.host)[0],
            'Connection': 'Keep-Alive'
        }
        Utils.log('正在加密表单数据')
        bodyString = Utils.encryptAES_ECB(
            json.dumps(env.submitData), 'abcdfe0987612345')
        env.submitData['bodyString'] = bodyString
        # print(env.submitData)
        formData = {
            'version':
            'first_v3',
            'calVersion':
            'firstv',
            'bodyString': bodyString,
            'sign': Utils.md5(urllib.parse.urlencode(env.submitData) + "&abcdfe0987612345")
        }
        formData.update(extension)
        Utils.log('正在尝试提交数据')
        return env.session.post(env.host + env.submitApi,
                                headers=headers,
                                data=json.dumps(formData),
                                verify=False)

    @staticmethod
    # 按任务type返回接口path表。
    def getApis(type):
        apis = [
            [
                'wec-counselor-collector-apps/stu/collector/queryCollectorProcessingList',
                'wec-counselor-collector-apps/stu/collector/detailCollector',
                'wec-counselor-collector-apps/stu/collector/getFormFields',
                'wec-counselor-collector-apps/stu/collector/submitForm',
                'wec-counselor-collector-apps/stu/obs/getUploadPolicy',
                'wec-counselor-collector-apps/stu/collector/previewAttachment'
            ],
            [
                'wec-counselor-sign-apps/stu/sign/getStuSignInfosInOneDay',
                'wec-counselor-sign-apps/stu/sign/detailSignInstance',
                'wec-counselor-sign-apps/stu/sign/submitSign',
                'wec-counselor-sign-apps/stu/obs/getUploadPolicy',
                'wec-counselor-sign-apps/stu/sign/previewAttachment'
            ],
            [
                'wec-counselor-attendance-apps/student/attendance/getStuAttendacesInOneDay',
                'wec-counselor-attendance-apps/student/attendance/detailSignInstance',
                'wec-counselor-attendance-apps/student/attendance/submitSign',
                'wec-counselor-sign-apps/stu/obs/getUploadPolicy',
                'wec-counselor-sign-apps/stu/sign/previewAttachment'
            ],
            [
                'wec-counselor-teacher-sign-apps/teacher/sign/getTeacherSignInfosInOneDay',
                'wec-counselor-teacher-sign-apps/teacher/sign/detailSignInstance',
                'wec-counselor-teacher-sign-apps/teacher/sign/submitSign',
                'wec-counselor-teacher-sign-apps/teacher/oss/getUploadPolicy',
                'wec-counselor-teacher-sign-apps/teacher/sign/previewAttachment'
            ]
        ]
        return apis[type]
