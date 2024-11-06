import json
import random
import time
import os

import frida
from flask import Flask, jsonify
from loguru import logger

import tools
from tools.asyncRequestQueue import DataStore


class Frida_Server(DataStore):

    def __init__(self):
        super().__init__()

        current_dir_path = os.path.dirname(os.path.abspath(__file__))
        with open(f'{current_dir_path}/frida_js/Hook_WeChat_FaaS.js', 'r') as f:
            hook_code = f.read()

        # 连接到设备
        self.device = frida.get_usb_device()  # 通过USB连接设备
        # device = frida.get_device_manager().add_remote_device('192.168.0.72:5555')
        AppBrandUI_pid = tools.get_pid(self.device.id, 'com.tencent.mm/.plugin.appbrand.ui.AppBrandUI')
        if not AppBrandUI_pid:
            raise Exception('微信小程序未打开? Pid未能搜索到')

        AppBrandUI_pid: int = int(AppBrandUI_pid)
        # 获取进程
        process = self.device.attach(AppBrandUI_pid)
        # 创建脚本
        self.script = process.create_script(hook_code)
        self.script.on('message', self.on_message)
        # 加载并运行脚本
        self.script.load()

    def get_tencent_appBrand_pid(self):
        for process in self.device.enumerate_processes():
            print(process)
            if "com.tencent.mm:appbrand" in process.name:
                return process.pid

        return None

    def on_message(self, message, data):
        if message['type'] == 'send':
            payload = json.loads(message['payload'])
            if payload['type'] == 'requests':
                logger.debug(f'{payload}')
            else:
                logger.success(f'{payload}')
                self.put(key=f'{payload["AppId"]}{payload["asyncRequestCounter"]}', value=payload)
        else:
            logger.error(f'{message}')

    def CallWX(self, appid, api_name, data):
        try:
            Appid_asyncRequestCounter = self.script.exports_sync.call(appid, api_name, data)
            return self.get(Appid_asyncRequestCounter, timeout=30)
        except Exception as e:
            logger.error(f"Error calling WX API: {e}")
            return None  # 或者其他合适的处理方式

    def close(self):
        # 停止脚本
        self.script.unload()


class WeChatApi(Frida_Server):

    def __init__(self, appid):
        super().__init__()
        self.appid = appid

    @staticmethod
    def get_tid():
        return int(time.time() * 1000)

    @staticmethod
    def json_dumps_blank_space(json_data):
        dumps = json.dumps(json_data, separators=(",", ":"))
        print(dumps)
        return dumps

    @staticmethod
    def generate_random_number(length=16):
        if not isinstance(length, int):
            raise ValueError("length must be an integer")
        return ''.join(random.choices('0123456789', k=length))

    def tcbapi_get_service_info(self):
        return self.CallWX(self.appid, 'operateWXData', self.json_dumps_blank_space({
            "keepAlive": True,
            "data": {
                "api_name": "qbase_commapi",
                "data": {
                    "qbase_api_name": "tcbapi_get_service_info",
                    "qbase_req": "{\"system\":\"Android 10\",\"wx_app_version\":\"8.0.50\",\"scene\":3,\"domain\":\"a0c89d6ac-wxe17e6efa4c656fcd.tj.wxgateway.com\"}",
                    "qbase_options": {
                        "rand": "0.1984426991775532"
                    },
                    "qbase_meta": {
                        "session_id": "1730878850530",
                        "sdk_version": "wx-miniprogram-sdk/3.5.8 (1728979288000 platform/android})",
                        "filter_user_info": False
                    },
                    "cli_req_id": "1730878850531_0.88395726994248"
                },
                "operate_directly": False,
                "tid": 1730878850533,
                "env": 1
            },
            "timeout": 60000,
            "requestInQueue": False,
            "isImportant": False,
            "useQuic": False
        }))

    def tcbapi_get_service_info2(self):
        tid = self.get_tid()
        return self.CallWX(self.appid, 'operateWXData', self.json_dumps_blank_space({
            "keepAlive": True,
            "data": {
                "api_name": "qbase_commapi",
                "data": {
                    "qbase_api_name": "tcbapi_get_service_info",
                    "qbase_req": "{\"system\":\"Android 10\",\"wx_app_version\":\"8.0.50\",\"scene\":3,\"domain\":\"a0c89d6ac-wxe17e6efa4c656fcd.tj.wxgateway.com\"}",
                    "qbase_options": {
                        "rand": f"0.{self.generate_random_number()}"
                    },
                    "qbase_meta": {
                        "session_id": f"{tid}",  # 确保没有额外空格
                        "sdk_version": "wx-miniprogram-sdk/3.5.8 (1728979288000 platform/android})",
                        "filter_user_info": False
                    },
                    "cli_req_id": f"{tid+1}_0.{self.generate_random_number()}"
                },
                "operate_directly": False,
                "tid": tid + 3,
                "env": 1
            },
            "timeout": 60000,
            "requestInQueue": False,
            "isImportant": False,
            "useQuic": False
        }))

    def sendOrder(self):
        return self.CallWX(self.appid, 'operateWXData', self.json_dumps_blank_space({
            "keepAlive": True,
            "data": {
                "api_name": "qbase_commapi",
                "data": {
                    "qbase_api_name": "tcbapi_call_gateway",
                    "qbase_req": "{\"method\":\"POST\",\"headers\":[{\"k\":\"Content-Type\",\"v\":\"application/json;charset=utf-8\"},{\"k\":\"identity_code\",\"v\":\"oZdQ347YgUiRjBTXVWBpzYm9q8rs\"},{\"k\":\"lCAlAPD4\",\"v\":\"F301ADS4\"},{\"k\":\"FEE_WAY\",\"v\":\"411986c8b9e52cb4e89ad1869ad35d0c:80\"},{\"k\":\"X-WX-REGION\",\"v\":\"ap-shanghai\"},{\"k\":\"X-WX-GATEWAY-ID\",\"v\":\"prod-popvip-go-4gvvjhghd014a5fb\"},{\"k\":\"HOST\",\"v\":\"shops-go.paquapp.com\"},{\"k\":\"x-wx-include-credentials\",\"v\":\"openid, unionid\"},{\"k\":\"User-Agent\",\"v\":\"Mozilla/5.0 (Linux; Android 10; M2006J10C Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/126.0.6478.188 Mobile Safari/537.36 XWEB/1260183 MMWEBSDK/20240501 MMWEBID/4402 MicroMessenger/8.0.50.2701(0x2800325B) WeChat/arm64 Weixin NetType/WIFI Language/zh_CN ABI/arm64 MiniProgramEnv/android\"},{\"k\":\"referer\",\"v\":\"https://servicewechat.com/wx9627eb7f4b1c69d5/677/page-frame.html\"},{\"k\":\"X-WX-HTTP-HOST\",\"v\":\"a0c89d6ac-wxe17e6efa4c656fcd.tj.wxgateway.com\"},{\"k\":\"X-WX-HTTP-PATH\",\"v\":\"/miniapp/v2/sg/order/create_order\"}],\"data\":\"{\\\"each_store_info\\\":[{\\\"settle_goods_list\\\":[{\\\"goods_sku_id\\\":3467,\\\"settle_num\\\":1,\\\"is_gift\\\":false}],\\\"ship_way\\\":3,\\\"store_id\\\":6702,\\\"user_address_id\\\":0,\\\"free_shipping_id\\\":1,\\\"promotion_id\\\":0,\\\"promotion_type\\\":\\\"\\\",\\\"ladder_id\\\":0,\\\"shipping_code\\\":\\\"\\\",\\\"mail_fee\\\":0}],\\\"position\\\":1,\\\"td_sign\\\":\\\"mc36d6565504f479be3714b9fef1c72d867891b77416640ef837bf80d9612998a01112wxkjbxowgu42cae2cb0e73dd43b3aa365ddd7119a44c6aa3658340527145248826a5d543c8b5c54bb32f76455b5e18ad34\\\",\\\"openid\\\":\\\"oZdQ347YgUiRjBTXVWBpzYm9q8rs\\\",\\\"sign\\\":\\\"2e3734bd8806bc763ad533ae059d9b91\\\",\\\"time\\\":\\\"1730876983057\\\",\\\"version\\\":\\\"5.1.14\\\"}\",\"data_type\":0,\"action\":1,\"retryType\":0,\"call_id\":\"v2-1730876983062-gCn0pu_f\"}",
                    "qbase_options": {
                        "rand": f"0.{self.generate_random_number()}"
                    },
                    "qbase_meta": {
                        "session_id": f"{self.get_tid()}",
                        "sdk_version": "wx-miniprogram-sdk/3.5.8 (1728979288000 platform/android})",
                        "filter_user_info": False
                    },
                    "cli_req_id": f"{self.get_tid()}_0.{self.generate_random_number()}"
                },
                "operate_directly": False,
                "tid": self.get_tid(),
                "env": 1
            },
            "timeout": 60000,
            "requestInQueue": False,
            "isImportant": False,
            "useQuic": False,
            "wxdataQueueTimestamp": self.get_tid(),
            "queueLength": 0
        }))


# if __name__ == '__main__':
#     wx = WeChatApi(appid='wx9627eb7f4b1c69d5')
#     # print(wx.login())
#     # print(wx.login())
#     # print(wx.login())
#     print(wx.tcbapi_get_service_info())
#     # import sys
#     # sys.stdin.read()
#     wx.close()


app = Flask(__name__)


@app.route('/getToken', methods=['GET'])
def get_token():
    info = wx.tcbapi_get_service_info()
    res = json.loads(info["res"])
    return json.loads(res["data"])


@app.route('/getToken2', methods=['GET'])
def get_token2():
    info = wx.tcbapi_get_service_info2()
    res = json.loads(info["res"])
    return json.loads(res["data"])


@app.route('/sendOrder', methods=['GET'])
def send_order():
    order_sent = wx.sendOrder()  # 假设这是发送订单的逻辑
    if order_sent:
        return jsonify({"message": "Order sent successfully", "data": order_sent})
    else:
        return jsonify({"message": "Failed to send order"}), 400


if __name__ == '__main__':
    wx = WeChatApi(appid='wx9627eb7f4b1c69d5')
    app.run(host='0.0.0.0', port=5000)  # 监听所有地址，端口5000
