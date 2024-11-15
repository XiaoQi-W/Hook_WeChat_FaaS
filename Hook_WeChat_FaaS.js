let CallWX_asyncRequestCounter = 0;
let Call_AppId = null;
let AppId = null;

function CallWX(appid, jsapi_name, data) {
    Call_AppId = appid;
    // CallWX_asyncRequestCounter = 0
    Java.perform(function () {
        function dumpAllFieldValue(obj) {
            if (obj === null) {
                return;
            }
            var cls = obj.getClass();
            while (cls !== null && !cls.equals(Java.use("java.lang.Object").class)) {
                var fields = cls.getDeclaredFields();
                if (fields === null || fields.length === 0) {
                    cls = cls.getSuperclass();
                    continue;
                }
                // if (!cls.equals(obj.getClass())) {
                //     console.log("Dump super class  " + cls.getName() + " fields:");
                // }

                for (var i = 0; i < fields.length; i++) {
                    var field = fields[i];
                    field.setAccessible(true);
                    var name = field.getName();
                    var value = field.get(obj);
                    var type = field.getType();
                    if (name === "C") {
                        return value
                    }
                    // console.log(type + " " + name + "=" + value);
                }

                cls = cls.getSuperclass();
            }
        }

        function getFieldValue(obj, fieldName) {
            var cls = obj.getClass();
            var field = cls.getDeclaredField(fieldName);
            field.setAccessible(true);
            var name = field.getName();
            var value = field.get(obj);
            // console.log("field: " + field + "\tname:" + name + "\tvalue:" + value);
            return value;
        }

        CallWX_asyncRequestCounter++;
        Java.choose('com.tencent.mm.appbrand.commonjni.AppBrandCommonBindingJni', {
            onMatch: function (instance) {
                // CallWX_asyncRequestCounter++;
                // console.log(CallWX_asyncRequestCounter, instance.mNativeHandle.value, JSON.stringify(instance.mAppBrandDelegate))
                try {
                    let mAppBrandDelegate = getFieldValue(instance, 'mAppBrandDelegate')
                    let g = getFieldValue(mAppBrandDelegate, 'g')
                    dumpAllFieldValue(g)
                    let C = dumpAllFieldValue(g)
                    if (C.toString() !== '{__APP__=true}') {
                        return;
                    }
                } catch {
                    return;
                }


                instance.nativeInvokeHandler(jsapi_name, data, '{}', CallWX_asyncRequestCounter, true, 0)

            },
            onComplete: function () {
            }
        })
    })
    // Call_AppId = null
    return `${Call_AppId}${CallWX_asyncRequestCounter}`;
}


Java.perform(function () {

        let v = Java.use("com.tencent.mm.plugin.appbrand.y");
        let AppId = "";
        v["getAppId"].implementation = function () {
            AppId = this["getAppId"]();
            return AppId;
        };


        // 获取 AppBrandCommonBindingJni 类
        var AppBrandCommonBindingJni = Java.use("com.tencent.mm.appbrand.commonjni.AppBrandCommonBindingJni");

        // Hook nativeInvokeHandler 方法
        AppBrandCommonBindingJni.nativeInvokeHandler.implementation = function (jsapi_name, data, str3, asyncRequestCounter, z15, i17) {
            CallWX_asyncRequestCounter = asyncRequestCounter;
            console.log(`[${AppId}] [${asyncRequestCounter}] == \x1b[36m[requests]\x1b[0m: jsapi_name=${jsapi_name}, data=${data}, str3=${str3}, z15=${z15}`);

            return this.nativeInvokeHandler(jsapi_name, data, str3, asyncRequestCounter, z15, i17);
        };

        // Hook invokeCallbackHandler 方法
        var AppBrandJsBridgeBinding = Java.use("com.tencent.mm.appbrand.commonjni.AppBrandJsBridgeBinding");

        // 使用 overload hook 方法
        AppBrandJsBridgeBinding.invokeCallbackHandler.overload('int', 'java.lang.String', 'java.lang.String').implementation = function (i16, str, str2) {
            console.log(`[${AppId}] [${i16}] == \x1b[32m[response]\x1b[0m: ${str}`)

            this.invokeCallbackHandler(i16, str, str2);
        }

    }
)


rpc.exports = {call: CallWX}
//  frida -U -l Hook_WeChat_FaaS.js com.tencent.mm --no-pause

//  CallWX('wx3c12cdd0ae8b1a7b', 'operateWXData', '{"data":{"api_name":"webapi_getuserinfo","data":{"lang":"en","version":"3.4.3"},"operate_directly":false,"with_credentials":true,"tid":1716198903418},"requestInQueue":true,"isImportant":true}')
//  CallWX('wx3c12cdd0ae8b1a7b', 'setStorageSync', '{"key":"sensors_mp_prepare_data","data":"[]","dataType":"Array","storageId":0}')