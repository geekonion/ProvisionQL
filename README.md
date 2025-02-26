# ProvisionQL - Quick Look for ipa & provision

[![Build Status](https://github.com/ealeksandrov/ProvisionQL/workflows/build/badge.svg?branch=master)](https://github.com/ealeksandrov/ProvisionQL/actions)
[![Latest Release](https://img.shields.io/github/release/ealeksandrov/ProvisionQL.svg)](https://github.com/ealeksandrov/ProvisionQL/releases/latest)
[![License](https://img.shields.io/github/license/ealeksandrov/ProvisionQL.svg)](LICENSE.md)
![Platform](https://img.shields.io/badge/platform-macos-lightgrey.svg)

![Thumbnails example](https://raw.github.com/ealeksandrov/ProvisionQL/master/Screenshots/1.png)

Inspired by a number of existing alternatives, the goal of this project is to provide clean, reliable, current and open source Quick Look plugin for iOS & macOS developers.

Thumbnails will show app icon for `.ipa`/ `.xcarchive` or expiring status and device count for `.mobileprovision`. Quick Look preview will give a lot of information, including devices UUIDs, certificates, entitlements and much more.

### Mobileprovision

![Valid AdHoc provision](Screenshots/2.png)

### MacOS App

![MacOS App](Screenshots/Xcode.png)

Supported file types:

* `.ipa` or `.tipa` - iOS packaged application
* `.app` - iOS/OSX application bundle
* `.framework` - iOS/OSX framework
* `.xcarchive` - Xcode archive
* `.appex` - iOS/OSX application extension
* `.mobileprovision` - iOS provisioning profile
* `.provisionprofile` - OSX provisioning profile

[More screenshots](https://github.com/ealeksandrov/ProvisionQL/blob/master/Screenshots/README.md)

### Acknowledgments

Initially based on [Provisioning by Craig Hockenberry](https://github.com/chockenberry/Provisioning).

### Tutorials based on this example:

* English - [aleksandrov.ws](https://aleksandrov.ws/2014/02/25/osx-quick-look-plugin-development/)
* Russian - [habrahabr.ru](https://habrahabr.ru/post/208552/)

## Installation

* Clone the project repo;
* Open the `ProvisionQL.xcodeproj` file, select the `ProvisionQLApp` target and click Run.
* Authorize `ProvisionQLPreview` and `ProvisionQLThumbnail` based on system prompts.
* Move or copy `ProvisionQLApp.app` to `/Applications`

### 其他

ProvisionQL没有系统扩展的优先级高，可能不生效。

ProvisionQL生成的信息末尾有类似以下信息：

```
ProvisionQL v1.6.4 (99) (debug) (Fork on GitHub)
```

1. 关闭ProvisioningProfileQuickLookExtension

   在`系统设置`中搜索`扩展`，将`快速查看`中的`ProvisioningProfileQuickLookExtension`复选框去掉勾选

2. 删除DVTProvisioningProfileQuicklookGenerator对mobileprovision的支持

   ```stylus
   /Applications/Xcode.app/Contents/Library/QuickLook/DVTProvisioningProfileQuicklookGenerator.qlgenerator
   ```

查看当前解析器

1. 查看文件和解析扩展的对应关系

   ```stylus
   qlmanage -m
   server: living for 0s (0 requests handled) - instant off: yes - arch: X86_64 - user id: 501
   memory used: 0 MB (849856 bytes) - used descriptors: 19/256
   plugins:
     ...
     com.apple.iphone.mobileprovision -> /Users/xxx/Library/QuickLook/ProvisionQL.qlgenerator (99)
     com.apple.application-and-system-extension -> /Users/xxx/Library/QuickLook/ProvisionQL.qlgenerator (99)
     ...
     com.apple.itunes.ipa -> /Users/xxx/Library/QuickLook/ProvisionQL.qlgenerator (99)
     ...
     com.apple.mobileprovision -> /Users/xxx/Library/QuickLook/ProvisionQL.qlgenerator (99)
     ...
   ```

获取文件类型contentTypeUTI

```stylus
mdls -name kMDItemContentType /path/to/file
```

调试

attach进程ExternalQuickLookSatellite-x86_64

## Author

Created and maintained by Evgeny Aleksandrov ([@ealeksandrov](https://twitter.com/ealeksandrov)).

## License

`ProvisionQL` is available under the MIT license. See the [LICENSE.md](LICENSE.md) file for more info.
