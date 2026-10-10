# -*- coding: utf-8 -*-
"""干跑：只登录 + 查任务 + 查详情，不提交、不上传照片。

用于验证：
  1) <学校名> CAS 登录链是否正常；
  2) 当前是否有未签到/查寝任务；
  3) 任务详情（isPhoto / isNeedExtra / 签到范围）。
不会产生任何签到提交。
"""
import json
import sys
import traceback

import yaml
from urllib3.exceptions import InsecureRequestWarning
import requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

sys.path.insert(0, '.')
from actions.wiseLoginService import wiseLoginService
from actions.utils import Utils

conf = yaml.safe_load(open('config.yml', encoding='utf-8'))
user = conf['users'][0]['user']
print('用户=%s 学校=%s type=%s' % (user.get('username'), user.get('schoolName'), user.get('type')))

try:
    wise = wiseLoginService(user, user.get('httpProxy', ''))
    print('正在登录…')
    wise.login()
    print('登录成功: host=%s login_type=%s cookies=%d'
          % (wise.campus_host, wise.login_type, len(wise.session.cookies)))
except Exception as e:
    print('登录失败: %s' % e)
    traceback.print_exc()
    sys.exit(1)

# 查任务（复用 AutoSign 的 apis[0]）
try:
    apis = Utils.getApis(user['type'])
    url = wise.campus_host + apis[0]
    headers = dict(wise.session.headers)
    headers['Content-Type'] = 'application/json'
    wise.session.post(url, headers=headers, data=json.dumps({}), verify=False)
    res = wise.session.post(url, headers=headers, data=json.dumps({}), verify=False).json()
    datas = res.get('datas', {})
    un = datas.get('unSignedTasks', [])
    leave = datas.get('leaveTasks', [])
    signed = datas.get('signedTasks', [])
    print('\n未签到任务 %d 个 / 待补签 %d 个 / 已签 %d 个' % (len(un), len(leave), len(signed)))
    for t in un:
        print('  [未签] %s  signInstanceWid=%s signWid=%s'
              % (t.get('taskName'), t.get('signInstanceWid'), t.get('signWid')))
    for t in leave:
        print('  [待补] %s  signInstanceWid=%s signWid=%s'
              % (t.get('taskName'), t.get('signInstanceWid'), t.get('signWid')))

    if un or leave:
        t = (un or leave)[0]
        detail = wise.session.post(wise.campus_host + apis[1], headers=headers,
                                   data=json.dumps({'signInstanceWid': t['signInstanceWid'],
                                                    'signWid': t['signWid']}),
                                   verify=False).json().get('datas', {})
        print('\n首个任务详情: isPhoto=%s isNeedExtra=%s isMalposition=%s'
              % (detail.get('isPhoto'), detail.get('isNeedExtra'), detail.get('isMalposition')))
        print('  signInstanceWid=%s' % detail.get('signInstanceWid'))
        if detail.get('isPhoto') == 1:
            print('  → 需要照片（config.photo=%s）' % user.get('photo'))
    else:
        print('当前无任务（可能不在任务时间窗内）。')
except Exception as e:
    print('查询任务失败: %s' % e)
    traceback.print_exc()
