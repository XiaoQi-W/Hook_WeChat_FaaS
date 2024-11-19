import subprocess
import time


def run_adb_command(command):
    """
    运行 ADB 命令的通用函数
    """
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip()
    else:
        print(f"Command failed: {result.stderr.strip()}")
        return None


def is_screen_on():
    """
    检查屏幕是否点亮
    """
    output = run_adb_command("adb shell dumpsys power")
    if output:
        # 根据返回内容判断屏幕状态
        return "mScreenOn=true" in output or "Display Power: state=ON" in output
    return False


def wake_up_device():
    """
    唤醒设备并解锁
    """
    # 唤醒屏幕
    run_adb_command("adb shell input keyevent 26")  # 按电源键
    time.sleep(1)
    # 模拟滑动解锁
    run_adb_command("adb shell input swipe 500 1500 500 500")  # 根据设备分辨率调整


def unlock_and_prepare_device():
    """
    解锁设备，确保屏幕点亮
    """
    if is_screen_on():
        print("屏幕已点亮，无需唤醒。")
    else:
        print("屏幕未点亮，正在唤醒设备...")
        wake_up_device()


def get_wechat_packages():
    """
    获取设备上所有的微信包名
    """
    command = "adb shell pm list packages"
    result = run_adb_command(command)
    if result:  # 确保结果不为空
        packages = [
            line.split(":")[1]
            for line in result.splitlines()  # 直接对字符串调用 splitlines()
            if "com.tencent.mm" in line
        ]
        return packages
    else:
        return []


def open_wechat(package_name):
    """
    打开指定包名的微信
    """
    print(f"启动微信：{package_name}")
    run_adb_command(f"adb shell monkey -p {package_name} -c android.intent.category.LAUNCHER 1")


def open_wechat_mini_program(appid, path=""):
    """
    使用 URL 启动微信小程序
    :param appid: 小程序的 AppId
    :param path: 小程序路径（可选）
    """
    url = f"weixin://dl/business/?appid={appid}&path={path}"
    print(f"启动微信小程序: {url}")
    run_adb_command(f'adb shell am start -a android.intent.action.VIEW -d "{url}"')


def get_screen_resolution():
    """获取设备的屏幕分辨率"""
    result = subprocess.run("adb shell wm size", shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        size = result.stdout.strip().split(": ")[1]
        width, height = map(int, size.split("x"))
        return width, height
    else:
        return None


def swipe_by_percentage(start_x_pct, start_y_pct, end_x_pct, end_y_pct):
    """根据百分比坐标进行滑动"""
    # 获取屏幕分辨率
    width, height = get_screen_resolution()
    if width is None or height is None:
        print("无法获取设备分辨率")
        return

    # 计算实际的坐标
    start_x = int(width * start_x_pct)
    start_y = int(height * start_y_pct)
    end_x = int(width * end_x_pct)
    end_y = int(height * end_y_pct)

    # 执行 ADB 滑动命令
    command = f"adb shell input swipe {start_x} {start_y} {end_x} {end_y}"
    subprocess.run(command, shell=True)
    print(f"执行滑动：{command}")


def click_by_percentage(x_pct, y_pct):
    """根据百分比坐标进行点击"""
    # 获取屏幕分辨率
    width, height = get_screen_resolution()
    if width is None or height is None:
        print("无法获取设备分辨率")
        return

    # 计算实际的坐标
    x = int(width * x_pct)
    y = int(height * y_pct)

    # 执行 ADB 点击命令
    command = f"adb shell input tap {x} {y}"
    subprocess.run(command, shell=True)
    print(f"执行点击：{command}")


if __name__ == "__main__":
    mini_program_appid = "wx9627eb7f4b1c69d5"
    mini_program_path = "packages/svip"
    print("检查设备屏幕状态...")
    unlock_and_prepare_device()

    # 获取所有微信包名
    print("检测设备上的微信多开实例...")
    wechat_packages = get_wechat_packages()

    if not wechat_packages:
        print("未检测到微信相关应用。")
    else:
        print("检测到以下微信包名：")
        for i, pkg in enumerate(wechat_packages):
            print(f"{i + 1}: {pkg}")

        selected_package = wechat_packages[0]
        open_wechat(selected_package)
        time.sleep(1)
        swipe_by_percentage(0.5, 0.5, 0.4, 0.9)
        time.sleep(1)
        click_by_percentage(0.18, 0.6)
