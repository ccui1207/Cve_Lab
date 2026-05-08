# ADB 常用命令

## 1. 查看设备

```bash
adb devices
```

## 2. 查看 Android 版本

```bash
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
```

## 3. 查看安全补丁日期

```bash
adb shell getprop ro.build.version.security_patch
```

## 4. 查看系统构建指纹

```bash
adb shell getprop ro.build.fingerprint
```

## 5. 查看设备型号

```bash
adb shell getprop ro.product.manufacturer
adb shell getprop ro.product.model
```

## 6. 查看内核版本

```bash
adb shell uname -a
```

## 7. 查看 SELinux 状态

```bash
adb shell getenforce
```

## 8. 保存 logcat

```bash
adb logcat -c
adb logcat > logcat.txt
```

## 9. 安装 APK

```bash
adb install app.apk
adb install -r app.apk
```

## 10. 卸载 APK

```bash
adb uninstall package.name
```

## 11. 查看包信息

```bash
adb shell dumpsys package package.name
```

## 12. 拉取文件

```bash
adb pull /sdcard/file.txt .
```

## 13. 推送文件

```bash
adb push local_file.txt /sdcard/
```
