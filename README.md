# iOS Internals & Security Testing

<div align="left">
Dec 15 2021 by Vadim Yegorov &lt;vadimszzz@mail.ru&gt;, Security Researcher & Software Engineer.
<hr>
<a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/"><img alt="Creative Commons Licence" style="border-width:0" src="https://i.creativecommons.org/l/by-sa/4.0/88x31.png" /></a><br>
Licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/">Creative Commons Attribution-ShareAlike 4.0 International License</a>. Author should be mentioned when copying or redistributing this work.
</div>
<br>

<div align="center"><img src="https://ia801403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/Untitled.png"></div>

# Table of contents

<!-- TOC start -->
- [iOS platform overview](#ios-platform-overview)
  * [File System](#file-system)
    + [UNIX system directories](#unix-system-directories)
    + [OS X/iOS–specific directories](#os-xiosspecific-directories)
    + [iOS File System Idiosyncrasies](#ios-file-system-idiosyncrasies)
  * [Applications](#applications)
    + [ipa file (iOS App Store Package)](#ipa-file-ios-app-store-package)
    + [ipa file contents](#ipa-file-contents)
    + [Application data in iOS filesystem](#application-data-in-ios-filesystem)
  * [Apple plist](#apple-plist)
  * [Privilege Separation and Sandbox](#privilege-separation-and-sandbox)
  * [Data Protection](#data-protection)
  * [App Capabilities](#app-capabilities)
  * [Device Capabilities](#device-capabilities)
  * [Entitlements](#entitlements)
  * [Application security features, Apple FairPlay DRM](#application-security-features-apple-fairplay-drm)
  * [Secure Enclave Processor](#secure-enclave-processor)
  * [AES Keys](#aes-keys)
    + [GID Key](#gid-key)
    + [UID Key](#uid-key)
    + [Derived keys](#derived-keys)
  * [Objective-C Basics](#objective-c-basics)
    + [Message exchange](#message-exchange)
    + [Method declaration](#method-declaration)
  * [iOS Frameworks](#ios-frameworks)
  * [iOS Network Frameworks](#ios-network-frameworks)
  * [iOS Private Frameworks](#ios-private-frameworks)
- [Tools overview](#tools-overview)
  * [How to jailbreak](#how-to-jailbreak)
  * [How to install cydia package](#how-to-install-cydia-package)
  * [Access device](#access-device)
    + [libimobiledevice](#libimobiledevice)
    + [ideviceinstaller](#ideviceinstaller)
    + [libirecovery](#libirecovery)
    + [idevicerestore](#idevicerestore)
    + [libusbmuxd](#libusbmuxd)
  * [Access filesystem](#access-filesystem)
  * [Access command line](#access-command-line)
  * [Persisted data](#persisted-data)
  * [View application layout and more](#view-application-layout-and-more)
- [Analyze application at runtime](#analyze-application-at-runtime)
  * [Frida](#frida)
  * [Frida basics](#frida-basics)
  * [Frida's --eval flag](#fridas---eval-flag)
  * [Frida Intercepter](#frida-intercepter)
  * [Frida-Trace](#frida-trace)
  * [Bypass anti-Frida checks](#bypass-anti-frida-checks)
  * [Objection](#objection)
  * [r2frida](#r2frida)
  * [Grapefruit (Passionfruit)](#grapefruit-passionfruit)
  * [Dwarf](#dwarf)
  * [Fermion](#fermion)
- [Analyze application network traffic](#analyze-application-network-traffic)
  * [Disabling SSL pinning](#disabling-ssl-pinning)
  * [Intercepting with Charles Proxy](#intercepting-with-charles-proxy)
- [Get decrypted .ipa file](#get-decrypted-ipa-file)
    + [With Apple mobile device – Dump](#with-apple-mobile-device--dump-it-with-bagbak-with-extensions-or-frida-ios-dump-cant-dump-extensions-or-any-other-tool)
    + [With or without Apple mobile device – Run the hardware AES decryption](#with-apple-mobile-device--run-the-hardware-aes-decryption)
- [Analyze application binaries](#analyze-application-binaries)
  * [Tools](#tools)
    + [Mach-O Binary Analyzers:](#mach-o-binary-analyzers)
    + [Hex Editors](#hex-editors)
    + [Disassemblers](#disassemblers)
    + [Decompilers](#decompilers)
    + [Debuggers](#debuggers)
    + [Memory Editors](#memory-editors)
    + [Various Command Line Tools](#various-command-line-tools)
  * [Disassembling with IDA Pro](#disassembling-with-ida-pro)
  * [IDA Pro plugins for iOS and Mach-O](#ida-pro-plugins-for-ios-and-mach-o)
    + [Kernelcache analysis](#kernelcache-analysis)
    + [Get information about methods](#get-information-about-methods)
    + [Retrieving  Symbols and Strings](#retrieving--symbols-and-strings)
    + [Cross References](#cross-references)
- [ARM64 assembly](#arm64-assembly)
    + [Registers](#registers)
    + [Register manipulation](#register-manipulation)
    + [Memory](#memory)
    + [Calling convention](#calling-convention)
    + [Conditions](#conditions)
    + [Branches](#branches)
    + [Miscellaneous](#miscellaneous)
- [iOS tweak development](#ios-tweak-development)
  * [Theos](#theos)
  * [Logos](#logos)
    + [%ctor](#ctor)
    + [%dtor](#dtor)
  * [Block level](#block-level)
    + [%group](#group)
    + [%hook](#hook)
    + [%new](#new)
    + [%subclass](#subclass)
    + [%property](#property)
    + [%end](#end)
  * [Function level](#function-level)
    + [%init](#init)
    + [%c](#c)
    + [%orig](#orig)
    + [%log](#log)
  * [logify.pl](#logifypl)
  * [Logos File Extensions](#logos-file-extensions)
<!-- TOC end -->


# iOS platform overview

## File System

### UNIX system directories

As a conformant UNIX system, OS X works with the well-known directories that are standard on all UNIX flavors:

- /bin: Unix binaries. This is where the common UNIX commands (for example, ls, rm, mv, df) are
- /sbin: System binaries. These are binaries used for system administration, such as file-system management, network configuration, and so on.
- /usr: The User directory. This is not meant for users, but is more like Windows’ program files in that third-party software can install here.
- /usr: Contains in it bin, sbin, and lib. /usr/lib is used for shared objects (think, Windows DLLs and \windows\system32). This directory also contains the include/ subdirectory, where all the standard C headers are.
- /etc: Et Cetera. A directory containing most of the system configuration files; for example, the password file (/etc/passwd). In OS X, this is a symbolic link to /private/etc.
- /dev: BSD device files. These are special files that represent hardware devices on the system (character and block devices).
- /tmp: Temporary directory. The only directory in the system that is world-writable (permissions: rwxrwxrwx). In OS X, this is a symbolic link to /private/tmp.
- /var: Various. A directory for log files, mail store, print spool, and other data. In OS X, this is a symbolic link to /private/var.

### OS X/iOS–specific directories

OS X adds its own special directories to the UNIX tree, under the system root:

- /Applications: Default base for all applications in system.
- /Developer: If XCode is installed, the default installation point for all developer tools.
- /Library: Data files, help, documentation, and so on for system applications.
- /Network: Virtual directory for neighbor node discovery and access.
- /System: Used for System files. It contains only a Library subdirectory, but this directory holds virtually every major component of the system, such as frameworks (/System/ Library/Frameworks), kernel modules (/System/Library/Extensions), fonts, and so on.
- /Users: Home directory for users. Every user has his or her own directory created here.
- /Volumes: Mount point for removable media and network file systems.
- /Cores: Directory for core dumps, if enabled. Core dumps are created when a process crashes, if the ulimit(1) command allows it, and contain the core virtual memory image of the process.

### iOS File System Idiosyncrasies

From the file system perspective, iOS is very similar to OS X, with the following differences: 

- The file system (HFSX) is case-sensitive (unlike OS X’s HFS+, which is case preserving, yet insensitive). The file system is also encrypted in part.
- The kernel is already prepackaged with its kernel extensions, as a kernelcache (in /System/Library/Caches/com.apple.kernelcaches). Unlike OS X kernel caches (which are compressed images), iOS kernel caches are encrypted Img3.
- /Applications may be a symbolic link to /var/stash/Applications. This is a feature of the jailbreak, not of iOS.
- There is no /Users, but a /User — which is a symbolic link to /var/mobile
- There is no /Volumes (and no need for it, or for disk arbitration, as iOS doesn’t have any way to add more storage to a given system)
- /Developer is populated only if the i-Device is selected as “Use for development” from within XCode. In those cases, the DeveloperDiskImage.dmg included in the iOS SDK is mounted onto the device.

## Applications

### ipa file (iOS App Store Package)

Files with the .ipa extension can be uncompressed by changing the extension to .zip and unzipping.

### ipa file contents

<div align="center"><img src="https://ia801403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/image-125.png" alt="" width="626px"></div>

```
/iTunesArtwork    
/iTunesArtwork@2x    
/iTunesMetadata.plist    
/WatchKitSupport/WK    
/META-INF    
/Payload/    
/Payload/<Application>.app/     
/Payload/<Application>.app/<Application> 	←	Apple FairPlay DRM Encrypted Executable
/Payload/<Application>.app/Info.plist 			A file that contains some of the application specific configurations
/Payload/<Application>.app/_CodeSignature/		Contains a plist file with a signature over all files in the bundle
/Payload/<Application>.app/Assets.car			Another zipped archive that contains assets (icons)
/Payload/<Application>.app/Frameworks/ 			Contains the app native libraries as .dylib or .framework files
/Payload/<Application>.app/PlugIns/ 			May contain app extensions as .appex files
/Payload/<Application>.app/Core Data			It is used to save permanent data for offline use and sync across iCloud devices
/Payload/<Application>.app/PkgInfo				An alternate way to specify the type and creator codes of your application or bundle
/Payload/<Application>.app/en.lproj, etc		Language packs that contains resources for those specific languages
```

### Application data in iOS filesystem

```
/var/containers/Bundle/Application/<UUID>		Bundle directory; tampering invalidates signature
/var/mobile/Containers/Data/<UUID> 				Application runtime data
/var/mobile/Containers/Data/<UUID>/Documents/	Contains all the user-generated data
/var/mobile/Containers/Data/<UUID>/Library/		Contains all files that aren't user-specific – caches, preferences, cookies, plist files
/var/mobile/Containers/Data/<UUID>/Library/Caches/
												Contains semi-persistent cached files
/var/mobile/Containers/Data/<UUID>/Library/Application Support/
												Contains persistent files necessary for running the app
/var/mobile/Containers/Data/<UUID>/Library/Preferences/<bundle id>.plist
												Properties that can persist after an application is restarted. Contains NSUserDefaults
/var/mobile/Containers/Data/<UUID>/tmp/			Temporary files that do not need to persist between app launches
```

## Apple plist

**plist** files are structured XML files that contains **key-value pairs** supporting basic object types, like dictionaries, lists, numbers and strings. Usually the top level object is a dictionary. **plist** can be **binary** or **xml** or **json** file.

| Abstract type           | XML element             | Cocoa class                                              | Core Foundation type                                         |
| :---------------------- | :---------------------- | :------------------------------------------------------- | :----------------------------------------------------------- |
| array                   | `<array>`               | `NSArray`                                                | `CFArray` (`CFArrayRef`)                                     |
| dictionary              | `<dict>`                | `NSDictionary`                                           | `CFDictionary` (`CFDictionaryRef`)                           |
| string                  | `<string>`              | `NSString`                                               | `CFString` (`CFStringRef`)                                   |
| data                    | `<data>`                | `NSData`                                                 | `CFData` (`CFDataRef`)                                       |
| date                    | `<date>`                | `NSDate`                                                 | `CFDate` (`CFDateRef`)                                       |
| number - integer        | `<integer>`             | `NSNumber` (`intValue`)                                  | `CFNumber` (`CFNumberRef`, integer value)                    |
| number - floating point | `<real>`                | `NSNumber` (`floatValue`)                                | `CFNumber` (`CFNumberRef`, floating-point value)             |
| Boolean                 | `<true/>` or `<false/>` | `NSNumber` (`boolValue` == `YES` or `boolValue` == `NO`) | `CFBoolean` (`CFBooleanRef` ; `kCFBooleanTrue` or `kCFBooleanFalse`) |

<div align="center"><img src="https://ia801403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/Screenshot_2021-09-16_at_12.51.12_PM.png" alt="" width="912px"></div>

A standard Info.plist contains the following entries:

- CFBundleDevelopmentRegion: Default language if no user-specific language can be found.
- CFBundleDisplayName: The name that is used to display this bundle to the user.
- CFBundleDocumentTypes: Document types this will be associated with. This is a dictionary, with the values specifying the file extensions this bundle handles. The dictionary also specifies the display icons used for the associated documents.
- CFBundleExecutable: The actual executable (binary or library) of this bundle. Located in Contents/MacOS.
- CFBundleIconFile: Icon shown in Finder view.
- CFBundleIdentifier: Reverse DNS form.
- CFBundleName: Name of bundle (limited to 16 characters).
- CFBundlePackageType: Specifying a four letter code, for example, APPL = Application, FRMW = Framework, BNDL = Bundle.
- CFBundleSignature: Four-letter short name of the bundle.
- CFBundleURLTypes: URLs this bundle will be associated with. This is a dictionary, with the values specifying which URL scheme to handle, and how.

### plutil:

`plutil -convert xml1 binary_file.plist`  

`plutil -convert xml1 data_file.json -o data_file.plist`  

### python plistlib:

[https://docs.python.org/3/library/plistlib.html](https://docs.python.org/3/library/plistlib.html)

## Privilege Separation and Sandbox

Applications the user can access run as the **mobile** user while critical system processes run as **root**.
However, the sandbox allows better control over actions that processes and applications can perform.

For example, even if two processes run as the same user (mobile), they are **not allowed to access or modify each other's data**.

Each application is installed under `/var/mobile/Applications/<UUID>`. **UUID** is random.
Once installed, applications have limited read access to some system areas and functions (SMS, phone call...). If an application wants to access a **protected area,** a **pop-up requesting permission** appears.

<div align="center"><img src="https://ia801403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/image-000.png" alt="" width="288px" /></div>

## Data Protection

App developers can leverage the iOS *Data Protection* APIs to implement **fine-grained access control** for user data stored in flash memory. The APIs are built on top of the **Secure Enclave Processor** (SEP). The SEP is a coprocessor that provides **cryptographic operations for data protection and key management**. A device-specific hardware key-the **device UID** (Unique ID)-is **embedded in the secure enclave**, ensuring the integrity of data protection even when the operating system kernel is compromised.

When a file is created on the disk, a new 256-bit AES key is generated with the help of secure enclave's hardware based random number generator. The content of the file is then encrypted with the generated key. And then, this key is saved encrypted with a class key along with the class ID, with both data encrypted by the system's key, inside the metadata of the file.

<div align="center"><img src="https://ia801403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/image.png" alt="" width="576px" /></div>

For decrypting the file, the metadata is decrypted using the system's key. Then using the class ID the class key is retrieved to decrypt the per-file key and decrypt the file.

Files can be assigned to one of four different protection classes, which are explained in more detail in the [iOS Security Guide](https://www.apple.com/business/docs/iOS_Security_Guide.pdf).

## App Capabilities

**Each app has a unique home directory and is sandboxed**, so that they cannot access protected system resources or files stored by the system or by other apps. These restrictions are implemented via sandbox policies (aka. *profiles*), which are enforced by the [Trusted BSD (MAC) Mandatory Access Control Framework](http://www.trustedbsd.org/mac.html) via a kernel extension.

Some **[capabilities/permissions](https://help.apple.com/developer-account/#/dev21218dfd6)** can be configured by the app's developers (e.g. Data Protection or Keychain Sharing) and will directly take effect after the installation. However, for others, **the user will be explicitly asked the first time the app attempts to access a protected resource**.

*[Purpose strings](https://developer.apple.com/documentation/uikit/core_app/protecting_the_user_s_privacy/accessing_protected_resources?language=objc#3037322)* or *usage description strings* are custom texts that are offered to users in the system's permission request alert when requesting permission to access protected data or resources.

<div align="center"><img src="https://ia601403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/permission_request_alert.png" alt="" width="240"></div>

If having the original source code, you can verify the permissions included in the `Info.plist` file:

- Open the project with Xcode.
- Find and open the `Info.plist` file in the default editor and search for the keys starting with `"Privacy -"`.

You may switch the view to display the raw values by right-clicking and selecting "Show Raw Keys/Values" (this way for example `"Privacy - Location When In Use Usage Description"` will turn into `NSLocationWhenInUseUsageDescription`).

If only having the IPA:

- Unzip the IPA.
- The `Info.plist` is located in `Payload/<appname>.app/Info.plist`.
- Convert it if needed (e.g. `plutil -convert xml1 Info.plist`) as explained in the chapter "iOS Basic Security Testing", section "The Info.plist File".
- Inspect all *purpose strings Info.plist keys*, usually ending with `UsageDescription`:

```  
<plist version="1.0">
<dict>
	<key>NSLocationWhenInUseUsageDescription</key>
	<string>Your location is used to provide turn-by-turn directions to your destination.</string>

```

## Device Capabilities

Device capabilities are used by the App Store to ensure that only compatible devices are listed and therefore are allowed to download the app. They are specified in the `Info.plist` file of the app under the `[UIRequiredDeviceCapabilities](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/iPhoneOSKeys.html#//apple_ref/doc/plist/info/UIRequiredDeviceCapabilities)` key.

```  
<key>UIRequiredDeviceCapabilities</key>
<array>
	<string>armv7</string>
</array>

```

Typically you'll find the armv7 capability, meaning that the app is compiled only for the armv7 instruction set, or if it’s a 32/64-bit universal app.

For example, an app might be completely dependent on NFC to work (e.g. a ["NFC Tag Reader"](https://itunes.apple.com/us/app/nfc-taginfo-by-nxp/id1246143596) app). According to the [archived iOS Device Compatibility Reference](https://developer.apple.com/library/archive/documentation/DeviceInformation/Reference/iOSDeviceCompatibility/DeviceCompatibilityMatrix/DeviceCompatibilityMatrix.html), NFC is only available starting on the iPhone 7 (and iOS 11). A developer might want to exclude all incompatible devices by setting the `nfc` device capability.

## Entitlements

Entitlements are key value pairs that are signed in to an app and allow authentication beyond runtime factors, like UNIX user ID. Since entitlements are digitally signed, they can’t be changed. Entitlements are used extensively by system apps and daemons to perform specific privileged operations that would otherwise require the process to run as root. This greatly reduces the potential for privilege escalation by a compromised system app or daemon.

For example, if you want to set the "Default Data Protection" capability, you would need to go to the **Capabilities** tab in Xcode and enable **Data Protection**. This is directly written by Xcode to the `<appname>.entitlements` file as the `com.apple.developer.default-data-protection` entitlement with default value `NSFileProtectionComplete`. In the IPA we might find this in the `embedded.mobileprovision` as:

```  
<key>Entitlements</key>
<dict>
	...
	<key>com.apple.developer.default-data-protection</key>
	<string>NSFileProtectionComplete</string>
</dict>
  
```

For other capabilities such as HealthKit, the user has to be asked for permission, therefore it is not enough to add the entitlements, special keys and strings have to be added to the `Info.plist` file of the app.

## Application security features, Apple FairPlay DRM

1. The applications need to be signed with a paid Apple developer certificate.
2. The application binaries are encrypted using **Apple FairPlay DRM**. A form of DRM exists in the IPA to control redistribution to a single Apple ID. Later we'll see how to remove it.
3. The applications are protected by code signing.
4. Patched applications cannot be installed on non-jailbroken devices.
5. Every iOS application runs in its own sandbox. After iOS 8.3+, this sandboxed data cannot be accessed without jailbreaking the iOS device.
6. No application can access data belonging to another application. Protocol handlers like URL schemes are the only way for inter-application communication to be used for message passing between applications. The data can also be stored in keychains.
7. Whenever new files are created on the iOS device, they are assigned data protection classes as specified by the developers. This helps put access restriction on these files.
8. Applications need to specifically request for permission from the user to access resources like Camera, Maps, Contacts, etc.
9. iOS devices 5s+ have a secure hardware component called Secure Enclave. It is a highlyoptimized version of ARM’s TrustZone and prevents the main processor from directly accessing sensitive data.

## Secure Enclave Processor

The **Secure Enclave** is part of the A7 and newer SoCs used for data protection, Touch ID and Face ID. The purpose of the Secure Enclave is to handle keys and other info such as biometrics that is sensitive enough to not be handled by the Application Processor. It is isolated with a hardware filter so the AP cannot access it. It shares RAM with the AP, but its portion of the RAM — TZ0 is encrypted. The secure enclave itself is a flashable 4MB AKF processor core called the secure enclave processor (SEP). The technology used is similar to [ARM's TrustZone/SecurCore](http://www.arm.com/products/processors/technologies/trustzone/index.php) but contains proprietary code for Apple KF cores in general and SEP specifically.

## AES Keys

The SoC in each device have an AES coprocessor with the **GID Key** and **UID Key** built in.

The device’s unique ID (UID) and a device group ID (GID) are AES 256-bit keys fused (UID) or compiled (GID) into the application processor during manufacturing. No software or firmware can read them directly; they can see only the results of encryption or decryption operations performed using them. The UID is unique to each device and is not recorded by Apple or any of its suppliers. The GID is common to all processors in a class of devices and is used as an additional level of protection when delivering system software during installation and restore. Integrating these keys into the silicon helps prevent them from being tampered with or bypassed, or accessed outside the AES engine.

### GID Key

The **GID key** (**Group ID key**) is a 256-bit AES key shared by all devices with the same application processor. The GID key is part of how iOS encrypts software on the device. This is one component of the iOS security system, which also includes [SHSH](https://www.theiphonewiki.com/wiki/SHSH) signatures. This key is different on each Apple SoC model.

**The GID Key has so far not been extracted from any device, so the only way to use it is by going through the AES engine itself.**

- But

    GID **can be obtained** through the expensive Cold Boot Attack procedure ([https://en.m.wikipedia.org/wiki/Cold_boot_attack](https://en.m.wikipedia.org/wiki/Cold_boot_attack)) and the next no less expensive procedure of scanning the SoC with an electron-beam lithographer Raith CHIPSCANNER ([https://minateh.ru/equipment/technological/e-beam-lithography/](https://minateh.ru/equipment/technological/e-beam-lithography/)). Such experiment is unjustifiably expensive and complex, so it never occurred to anyone to try to implement it except for the private laboratory Cellebrite. Cellebrite does not share its research.

### UID Key

The **UID key** (**device's Unique ID key**) is an AES 256-bit hardware key, unique to each iPhone.

### Derived keys

Some derived keys are computed by the IOAESAccelerator kernel service at boot. These keys are generated by encrypting static values either with the UID key (0x7D0 identifier) or the GID key (0x3E8 identifier).

**Key 0x835** – Generated by encrypting `0x01010101010101010101010101010101` with the UID-key. Used for data protection.

**Key 0x836** – Generated by encrypting `0x00E5A0E6526FAE66C5C1C6D4F16D6180` with the UID-key. This is computed by the kernel during a restore, but is zeroed out during a normal boot. It is also computed by the Secure Bootloader, and its only known use is to decrypt LLB in NOR. Like **0x835**, it is different for each device.

**Key 0x837** – Generated by encrypting `0x345A2D6C5050D058780DA431F0710E15` with the [S5L8900](https://www.theiphonewiki.com/wiki/S5L8900) GID Key, resulting in `0x188458A6D15034DFE386F23B61D43774`. It is used as the encryption key for [IMG2 files](https://www.theiphonewiki.com/wiki/S5L_File_Formats#IMG2). With the introduction of [IMG3](https://www.theiphonewiki.com/wiki/IMG3_File_Format) in iPhone OS 2.0, [KBAGs](https://www.theiphonewiki.com/wiki/KBAG) are now used instead of the **0x837** key. Because iPhone OS versions 1.x were used only on the [iPhone](https://www.theiphonewiki.com/wiki/M68AP) and [iPod touch](https://www.theiphonewiki.com/wiki/N45AP) (both use the [S5L8900](https://www.theiphonewiki.com/wiki/S5L8900)) the encrypted values for other processors don't matter.

**Key 0x838** – Generated by encrypting `0x8C8318A27D7F030717D2B8FC5514F8E1` with the UID-key. Another UID-AES-key-based key, it is used to encrypt everything but LLB in the NOR (iBoot, DeviceTree, pictures).

**Key 0x899** – Generated by encrypting `0xD1E8FCB53937BF8DEFC74CD1D0F1D4B0` with the UID-key. Usage unknown.

**Key 0x89A** – Generated by encrypting `0xDB1F5B33606C5F1C1934AA66589C0661` with the UID-key, getting a device-specific key. Used on A4 devices. It is used to encrypt the [SHSH](https://www.theiphonewiki.com/wiki/SHSH) blobs on the device.

**Key 0x89B** – Generated by encrypting `0x183E99676BB03C546FA468F51C0CBD49` with the UID-key. It is used to encrypt the data partition key.

**Key 0x8A3** – Generated by encrypting `0x568241656551e0cdf56ff84cc11a79ef` with the UID-key (using AES-256-CBC). It is used during software upgrades on A12 and later to encrypt the "generator" value (using AES-128-CBC) before hashing it to become the nonce.

More info:
[https://css.csail.mit.edu/6.858/2020/readings/ios-security-may19.pdf](https://css.csail.mit.edu/6.858/2020/readings/ios-security-may19.pdf)  
[https://www.securitylab.ru/contest/428454.php](https://www.securitylab.ru/contest/428454.php)  
[https://www.securitylab.ru/contest/429973.php](https://www.securitylab.ru/contest/429973.php)

## Objective-C Basics

Objective-C module files have the “.m” extension (if a mix of C++ and Objective-C was used, the “.mm” extension). Header files - “.h”. All objects of classes created in Objective-C must be allocated in heap. Therefore, the id type, which is a pointer to an object of any class (in fact, void \*), acquires special significance. A null pointer is referred to as the constant nil. Thus, a pointer to any class can be cast to the id type. A problem arises: how to find out which class the object hiding under id belongs to? This is done thanks to the isa invariant, which is present in any object of a class that inherits a special base class NSObject (the NS prefix stands for NeXT Step). The isa invariant is of the reserved type Class. An object of this type allows you to find out the names of its own and the base class, a set of class invariants, as well as the prototypes of all methods that this object has implemented and their addresses (through a local list of selectors). All Objective-C reserved words other than C reserved words begin with an @ symbol (eg @protocol, @selector, @interface). Typically, the names of scoped class invariants (@private, @protected) begin with an underscore. For strings, Cocoa has a very handy NSString class. The string constant of this class is written as @"Hello world", and not as the usual C string constant "Hello world". The BOOL type (essentially unsigned char) can take the constant values YES and NO. All Objective-C-specific reserved words (which differ from the C language and are found in the header file objc/objc.h) are listed below:

`@interface` 				Starts declaring a class or category (category is class extension without inheritance)  
`@end` 						Completes the declaration\definition of any class, category or protocol  
`@private` 					Limits the scope of class invariants to class methods (similar to C++)  
`@protected` 				Stands by default. Limits the scope of class invariants to class methods and methods of derived classes (similar to C++)  
`@public` 					Removes scoping restrictions (similar to C++)  
`@try` 						Defines a block with possible exception throwing (similar to C++)  
`@throw` 					Throws an exception object (similar to C++)  
`@catch()` 					Handles the exception thrown in the preceding @try block (similar to C++)  
`@finally` 					Defines the block after the @try block to which control is passed regardless of whether an exception was thrown or not  
`@class` 					Abbreviated form of class declaration (name only (similar to C++))  
`@selector(method_name)` 	Returns the compiled selector for the method name method_name  
`@protocol(protocol_name)` 	Returns an instance of the protocol class named `protocol_name`  
`@encode(type_spec)` 		Initializes a character string that will be used to encrypt data of type `type_spec`  
`@synchronized()` 			Defines a block of code executed by only one thread at any given point in time  
`@implementation` 			Starts defining a class or category  
`@protocol` 				Begins a protocol declaration (analogous to a C++ class consisting of pure virtual functions)  

### Message exchange

To force an object to execute a method, you need to send it a message named the same as the required method. This message is called a method selector. The syntax for sending is as follows:  

`[receiver method];`  

### Method declaration

`- (void) addObject: (id) otherObject;`  

If you put a plus sign `+` at the beginning of a method prototype, then such a method will be considered a class method and, naturally, will not accept the implicit self parameter (this is similar to declaring a static method in C++). And without the isa invariant of the object pointed to by self, the super pointer, of course, will not work either.
Thus, the prototype of any method is declared like this:  

```
- | + (<return type>) mainMethodNamePart
[: (<type of first parameter>) nameOfFirstFormalParameter
	[[optionalMethodNamePart]: (<type of second parameter>) secondFormalParameterName] ...
]
```  

For example:  

`+ (Class)class;`  
`+ (id)alloc;`  
`- (id)init;`  
`- (void)addObject: (id)anObject;`  
`+ (NSString *)stringWithCString: (const char*)aCString usingUncoding: (enum NSStringEncoding)encoding;`  
`- (NSString *)initStringWithFormat: (NSString *)format, ...;`  

## iOS Frameworks

- Bluetooth peripherals
- Calendar data
- Camera
- Contacts
- Health sharing
- Health updating
- HomeKit
- Location
- Microphone
- Motion
- Music and the media library
- Photos
- Reminders
- Siri
- Speech recognition
- the TV provider
- etc

### Official documentation

[Apple Developer Documentation](https://developer.apple.com/documentation/technologies)

### Official list

https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/OSX_Technology_Overview/SystemFrameworks/SystemFrameworks.html

### Full list

https://www.theiphonewiki.com/wiki//System/Library/Frameworks

### Where are they stored

Frameworks are stored in several locations on the file system:

- /System/Library/Frameworks. Contains Apple’s supplied frameworks — both in iOS and OS X
- /Network/Library/Frameworks may (rarely) be used for common frameworks installed on the network.
- /Library/Frameworks holds 3rd party frameworks (and, as can be expected, the directory is left empty on iOS)
- \~/Library/Frameworks holds frameworks supplied by the user, if any  

Additionally, applications may include their own frameworks.

## iOS Network Frameworks

[Apple Developer Documentation – Network](https://developer.apple.com/documentation/network)  

[Apple Developer Documentation – NetworkExtension](https://developer.apple.com/documentation/networkextension)  

[Apple Developer Documentation – NetworkingDriverKit](https://developer.apple.com/documentation/networkingdriverkit)  

### Network Communication

Most of the apps you might encounter connect to remote endpoints. Even before you perform any dynamic analysis (e.g. traffic capture and analysis), you can obtain some initial inputs or entry points by enumerating the domains to which the application is supposed to communicate to.

Typically these domains will be present as strings within the binary of the application. One can extract domains by retrieving strings with `rabin2 -zz <path_to_binary>` or in the IDA Pro. The latter option has a clear advantage: it can provide you with context, as you'll be able to see in which context each domain is being used by checking the cross-references.

From here on you can use this information to derive more insights which might be of use later during your analysis, e.g. you could match the domains to the pinned certificates or perform further reconnaissance on domain names to know more about the target environment.

The implementation and verification of secure connections can be an intricate process and there are numerous aspects to consider. For instance, many applications use other protocols apart from HTTP such as XMPP or plain TCP packets, or perform certificate pinning in an attempt to deter MITM attacks.

### Network Framework

The Network framework was introduced at [The Apple Worldwide Developers Conference (WWDC)](https://developer.apple.com/videos/play/wwdc2018/715) in 2018 and is a replacement to the Sockets API. This low-level networking framework provides classes to send and receive data with built in dynamic networking, security and performance support.

TLS 1.3 is enabled by default in the Network framework, if the argument `using: .tls` is used. It is the preferred option over the legacy [Secure Transport](https://developer.apple.com/documentation/security/secure_transport) framework.

### URLSession

`URLSession` was built upon the Network framework and utilizes the same transport services. The class also uses TLS 1.3 by default, if the endpoint is HTTPS.

`URLSession` should be used for HTTP and HTTPS connections, instead of utilizing the Network framework directly. The class natively supports both URL schemes and is optimized for such connections. It requires less boilerplate code, reducing the propensity for errors and ensuring secure connections by default. The Network framework should only be used when there are low-level and/or advanced networking requirements.

The official Apple documentation includes examples of using the Network framework to [implement netcat](https://developer.apple.com/documentation/network/implementing_netcat_with_network_framework) and `URLSession` to [fetch website data into memory](https://developer.apple.com/documentation/foundation/url_loading_system/fetching_website_data_into_memory).  

## iOS Private Frameworks

### Dumped headers

https://developer.limneos.net/

### Full list

https://www.theiphonewiki.com/wiki//System/Library/PrivateFrameworks


# Tools overview

## How to jailbreak

Latest tool for your device can be found here [https://canijailbreak.com](https://canijailbreak.com/)  

This research is basically written for checkra1ned iPhones 5s through X with iOS 10–15 and can be updated in a long term if a new bootrom pwnage tool will be released. Check it out [https://www.theiphonewiki.com/wiki/Bootrom#Bootrom_Exploits](https://www.theiphonewiki.com/wiki/Bootrom#Bootrom_Exploits)

## How to install cydia package

### Using cydia – easiest way without troubles

1. Add to cydia sources related repo (`https://repo.chariz.com` for example)
2. Search for a package and install
3. If you don't see changes or something doesn't work run `killall SpringBoard`  
In most cases restarting SpringBoard is required

### With .deb package or .ipa file

Open .deb/.ipa file with [Filza File Manager](http://cydia.saurik.com/package/com.tigisoftware.filza/) and press Install, if you see an error with .deb installation try to find and install all dependencies

### In order to install any .ipa file

Install **AppSync Unified** from `https://cydia.akemi.ai/` repo

### Add this repos to your cydia:

`https://apt.bingner.com/`  
`https://apt.thebigboss.org/repofiles/cydia/`  
`https://cydia.saurik.com`  
`https://repo.dynastic.co/`  
`https://getdelta.co/`  
`https://cokepokes.github.io/`  
`https://cydia.akemi.ai/`  
`https://nscake.github.io/`  
`https://repo.chariz.com/`  
`https://mrepo.org/`  
`https://rejail.ru/`  
`https://repo.hackyouriphone.org/`  
`https://build.frida.re/` — frida  
`https://cydia.radare.org/` — radare2  

## Access device

Install on desktop

`brew install libimobiledevice ideviceinstaller libirecovery`  

`sudo port install idevicerestore`  

### libimobiledevice:

`idevice_id`					List attached devices or print device name of given device
`idevicebackup`					Create or restore backup for devices (legacy)
`idevicebackup2`				Create or restore backups for devices running iOS 4 or later
`idevicecrashreport`			Retrieve crash reports from a device
`idevicedebug`					Interact with the debugserver service of a device
`idevicedebugserverproxy`		Proxy a debugserver connection from a device for remote debugging
`idevicediagnostics`			Interact with the diagnostics interface of a device
`ideviceenterrecovery`			Make a device enter recovery mode
`ideviceimagemounter`			Mount disk images on the device
`ideviceinfo`					Show information about a connected device
`idevicename`					Display or set the device name
`idevicepair`					Manage host pairings with devices and usbmuxd
`idevicescreenshot`				Gets a screenshot from the connected device
`idevicesetlocation`			Simulate location on device
`idevicesyslog`					Relay syslog of a connected device

### ideviceinstaller:

`ideviceinstaller --list-apps`  
`ideviceinstaller --install <Application.ipa>`  
`ideviceinstaller --uninstall <bundle id>`  
`idevicedebug -d run <bundle id>`  

### libirecovery:

`irecovery --shell`				Allows communication with iBoot/iBSS of iOS device

### idevicerestore:

`idevicerestore --latest`		Restore a new firmware to a device
`idevicerestore --erase --latest`  
								Force restoring with erasing all data

### libusbmuxd:

`inetcat`						Utility to expose a raw connection to the device
`iproxy 2222:22`				Bind local port 2222 and forward to 22 of the first USB device

## Access filesystem

### On desktop

Install on device [Apple File Conduit "2"](https://cydia.saurik.com/package/com.saurik.afc2d)

Use iMazing or iFunBox to access filesystem

### On device

Install [Filza File Manager](http://cydia.saurik.com/package/com.tigisoftware.filza/)

<div align="center"><img src="https://ia601403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/261B72F2-27EE-49B3-828A-0F30FBDDBC0A.png" alt="" width="336px" /></div>

## Access command line

### On desktop

Install [**OpenSSH**](https://cydia.saurik.com/openssh.html) on device and run on desktop:

`iproxy 2222:22`  

`ssh -p 2222 root@localhost`  

Default iOS password for `root` is `alpine`. Don't change it if you have a bad memory

### On device

Install on device [**NewTerm 2**](https://4pda.to/forum/index.php?showtopic=947025) from `https://repo.chariz.com` to use local terminal

<div align="center"><img src="https://ia801403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/17C842A2-7060-4690-A88C-4C54276B2CE5.png" alt=""  width="336px" /></div>

## Persisted data

#### Inspect App bundle

```
cd /private/var/containers/Bundle/Application/<guid>/myapp.app
// Contains compiled code, statically linked files, compressed NIB files.
```

#### Inspect sandboxed data

```
cd /private/var/mobile/Containers/Data/Application/
ls -lrt  // Your freshly installed IPA is at the bottom of list
cd [app guid]/Documents/
cd [app guid]/Library/
```

#### Databases to pull off a device

```
/private/var/Keychains
TrustStore.sqlite3
keychain-2.db
pinningrules.sqlite3
```

#### File sharing

```
// Extract IPA (whether App Store encrypted or not)
scp -r -P 2222 root@localhost:/var/containers/Bundle/Application/<app GUID>/hitme.app ~/hitme.app

// Different to SSH, the uppercase P for Port with SCP. Order important.
scp -P 2222 root@localhost:/var/root/overflow.c localfilename.c

// from Jailbroken device to local machine
// Caution:no space after the root@localhost: Otherwise you copy the entire filesystem!
scp -P 2222 root@localhost:/private/var/mobile/Containers/Data/Application/<App GUID>/Library/Caches/Snapshots/com.my.app

// from local machine to remote Jailbroken device
scp -P 2222 hello.txt root@localhost:/var/root/
```

## View application layout and more

Install **libFLEX** and **FLEXing** from `https://nscake.github.io/` 

Open NewTerm and run `killall SpringBoard`  

Now you can load FLEX inside any application by longpress on the statusbar

<div align="center">
<img src="https://ia601403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/8E269ECE-3A71-4B12-A460-CA06DB9297B2.png" alt=""  width="336px" />

<img src="https://ia601403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/63D8B589-F7FA-44A9-80F0-6A8BD6E501BB.png" alt=""  width="336px" />

<img src="https://ia801403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/5E548AED-E106-4563-B7D2-A562CAE9270C.png" alt=""  width="336px" />

</div>

# Analyze application at runtime

## Frida

Frida is a dynamic binary instrumentation toolkit that allows us to execute scripts in previously locked down software. In a nutshell, Frida lets you inject snippets of JavaScript into native apps on Windows, Mac, Linux, iOS and Android.

### Install frida server:

Add frida repo to the cydia – `https://build.frida.re/`  
- If you have 32-bit device with Apple A6 or lower (iPhone 5, iPhone 5C, iPad 2 and earlier) install **Frida for 32-bit devices**  
- If you have 64-bit device with Apple A11 or lower (iPhone X, iPad 7, iPod Touch 7 and earlier) install **Frida**  
- On a newer device you can install **Frida for A12+ devices**  

### Install frida on desktop

If you don't have Python 3:

`brew install pyenv`    
`pyenv install 3.9.0` (or the latest available)

Then install

`pip3 install frida-tools`  

### frida:

`frida-ls-devices`								List available devices  
`frida-ps -U`									List all running processes names and PIDs on a USB device  
`frida-ps -Uai`									List all installed apps on a USB device  
`frida-ps -Ua`									List all running apps on a USB device  
`frida-ls-devices`								List all attached devices  
`frida-ps -D 0216027d1d6d3a03`					Connect Frida to the specific device  
`frida-discover`								Tool for discovering internal functions in a process  
`frida-trace -U Twitter -i "*URL*"`				Tracing native APIs  
`frida-trace -U -f com.toyopagroup.picaboo -I "libcommonCrypto*"`  
												Launch the app and trace crypto API calls  
`frida-trace -U Twitter -m "-[NSURL* *HTTP*]"`	Tracing Objective-C APIs  
`frida -U -n Twitter -l inject.js`				Inject **script** into process on a USB device via REPL  
`frida -n cat`									Connect to cat by name  
`frida -f foobar`								Force open foobar  
`frida -U -f foobar --no-pause`					Open foobar over usb and force start. starts app running  
`frida-ps -U | grep -i myapp`					Get the target app's process ID from USB connected device  
`frida -U -f foobar --no-pause -q --eval 'console.log("Hi Frida");'`  
												Run script and quit Frida  

### **Calling a Native Function**

At this point we have our `NativeFunction` stored in the `play_sound` variable. Call it just like a regular function `play_sound()` and also remember to give the (`int`) input parameter: `play_sound(1007)`  

Putting it all together:

`var address = Module.findExportByName('AudioToolbox', 'AudioServicesPlaySystemSound')`  
`var play_sound = new NativeFunction(address, 'void', ['int'])`  
`play_sound(1007)`  

You have to get an instance of the object first, either:

- allocating it and calling its constructor, for example `var instance = ObjC.classes.ClassName.alloc().init();`  
- getting an existing instance using `ObjC.choose`, like - if you know there's only one instance already created somewhere on the heap - you can to something like `var instance = ObjC.chooseSync(ObjC.classes.ClassName)[0];`  
- getting an existing instance from a singleton you know holds the instance in a property, for example `var instance = ObjC.classes.MySingleton.getInstance().myInterestingInstance();`  

and then call the method on the instance:

`instance.setSomething();`  

or, if the method signature takes an argument, like `- setSomething:`, you can also pass the argument (just remember to put a `_` instead of ObjC's `:`):

`instance.setSomething_(argument);`  

## Frida basics

```
frida -U "My App"               // Attach Frida to app over USB

Process.id
419

Process.getCurrentThreadId()
3843

var b = "hello frida"

console.log(b)
"hello frida"

c = Memory.allocUtf8String(b)
"0x1067ec510"

Memory.readUtf8String(c)
"hello frida"

console.log(c)
0x1067ec510

console.log(c.readUtf8String(5))
hello

console.log(c.readUtf8String(11))
hello frida

ptrToC = new NativePointer(c);
"0x1067ec510"

console.log(ptrToC)
0x1067ec510

console.log(ptrToC.readCString(8))
hello fr

Memory.readUtf8String(ptrToC)
"hello frida"
```

#### Frida - Objective-C

Objective-C's syntax includes the `:` and `@` characters. These characters were not used in the `Frida Javascript API`.

```
// Attach to playground process ID
frida -p $(ps -ax | grep -i -m1 playground |awk '{print $1}')

ObjC.available
true

ObjC.classes.UIDevice.currentDevice().systemVersion().toString()
"11.1"

ObjC.classes.NSBundle.mainBundle().executablePath().UTF8String()

ObjC.classes.UIWindow.keyWindow().toString()
RET: <WKNavigation: 0x106e165c0>

// shows Static Methods and Instance Methods
ObjC.classes.NSString.$ownMethods

ObjC.classes.NSString.$ivars

var myDate = ObjC.classes.NSDate.alloc().init()

console.log(myDate)
2019-04-19 19:03:46 +0000

myDate.timeIntervalSince1970()
1555700626.021566

myDate.description().toString()
"2019-04-19 19:03:46 +0000"

var a = ObjC.classes.NSUUID.alloc().init()

console.log(a)
4645BFD2-94EE-413D-9CE5-8982D41ED6AE

a.UUIDString()
{
    "handle": "0x7ff3b2403b20"
}
a.UUIDString().toString()
"4645BFD2-94EE-413D-9CE5-8982D41ED6AE"
```

#### NSString

```
var b = ObjC.classes.NSString.stringWithString_("foo");

b.isKindOfClass_(ObjC.classes.NSString)
true

b.isKindOfClass_(ObjC.classes.NSUUID)
false

b.isEqualToString_("foo")
true

b.description().toString()
"foo"

var c = ObjC.classes.NSString.stringWithFormat_('foo ' + 'bar ' + 'lives');

console.log(c)
foo bar lives
```

#### NSURL

```
var url = ObjC.classes.NSURL.URLWithString_('www.foobar.com')

console.log(url)
www.foobar.com

url.isKindOfClass_(ObjC.classes.NSURL)
true

console.log(url.$class)
NSURL
```

#### Frida from NSString to NSData back to Hex String

```
var b = ObjC.classes.NSString.stringWithString_("foo");

var d = ObjC.classes.NSData
d = b.dataUsingEncoding_(1)			//	NSASCIIStringEncoding = 1, NSUTF8StringEncoding = 4,

console.log(d)
<666f6f>							//	This prints the Hex value "666f6f = foo"

d.$className
"NSConcreteMutableData"

var x = d.CKHexString()				//	Get you the Byte array as a Hex string

console.log(x)
666f6f

x.$className
"NSTaggedPointerString"

var newStr = ObjC.classes.NSString.stringWithUTF8String_[d.bytes]
```

#### Frida with xCode Simulator

```
// demoapp is the iOS app name
myapp=$(ps x | grep -i -m1 demoapp | awk '{print $1}')
frida-trace -i "getfsent*" -p $myapp

// Connect to process with Frida script
frida --codeshare mrmacete/objc-method-observer -p 85974
```

#### Frida find Modules

```
Process.enumerateModules()      
// this will print all loaded Modules

Process.findModuleByName("libboringssl.dylib")
{
    "base": "0x1861e2000",
    "name": "libboringssl.dylib",
    "path": "/usr/lib/libboringssl.dylib",
    "size": 712704
}

Process.findModuleByAddress("0x1c1c4645c")
{
    "base": "0x1c1c2a000",
    "name": "libsystem_kernel.dylib",
    "path": "/usr/lib/system/libsystem_kernel.dylib",
    "size": 200704
}
```

#### Find Address and Module of function name (Export)

```
DebugSymbol.fromAddress(Module.findExportByName(null, 'strstr'))
{
    "address": "0x183cb81e8",
    "fileName": "",
    "lineNumber": 0,
    "moduleName": "libsystem_c.dylib",
    "name": "strstr"
}
```

#### Find Address of Export and use Address to find Module

```
Module.findExportByName(null, 'strstr')
"0x183cb81e8"

Module.getExportByName(null,'strstr')
"0x183cb81e8"

Process.findModuleByAddress("0x183cb81e8")
{
    "base": "0x183cb6000",
    "name": "libsystem_c.dylib",
    "path": "/usr/lib/system/libsystem_c.dylib",
    "size": 516096
}
```

#### Exports inside a Module

```
a = Process.findModuleByName("Reachability")
a.enumerateExports()
....
{
    "address": "0x102fab020",
    "name": "ReachabilityVersionString",
    "type": "variable"
},
{
    "address": "0x102fab058",
    "name": "ReachabilityVersionNumber",
    "type": "variable"
}
....
...
..
```

## Frida's --eval flag

#### Enumerate all Exports, grepping for one function, and quit

```
frida -U -f funky-chicken.debugger-challenge --no-pause -q --eval 'var x={};Process.enumerateModulesSync().forEach(function(m){x[m.name] = Module.enumerateExportsSync(m.name)});' | grep -B 1 -A 1 task_threads

            "address": "0x1c1c4645c",
            "name": "task_threads",
            "type": "function"
```

#### Search for Module, with the Exports' Address

```
frida -U -f funky-chicken.debugger-challenge --no-pause -q --eval 'var x={};Process.findModuleByAddress("0x1c1c4645c");'

{
    "base": "0x1c1c2a000",
    "name": "libsystem_kernel.dylib",
    "path": "/usr/lib/system/libsystem_kernel.dylib",
    "size": 200704
}
```

## Frida Intercepter

```
[objc_playground]-> var a = ObjC.classes.NSString.stringWithString_("foo");

[objc_playground]-> a.superclass().toString()
"NSString"

[objc_playground]-> a.class().toString()
"NSTaggedPointerString"

// PASTE THIS CODE INTO THE FRIDA INTERFACE...
Interceptor.attach(ObjC.classes.NSTaggedPointerString['- isEqualToString:'].implementation, {
    onEnter: function (args) {
      var str = new ObjC.Object(ptr(args[2])).toString()
      console.log('[+] Hooked NSTaggedPointerString[- isEqualToString:] ->' , str);
    }
});

// TRIGGER YOUR INTERCEPTOR
[objc_playground_2]-> a.isEqualToString_("foo")
[+] Hooked NSTaggedPointerString[- isEqualToString:] -> foo
1   // TRUE
[objc_playground_2]-> a.isEqualToString_("bar")
[+] Hooked NSTaggedPointerString[- isEqualToString:] -> bar
0   // FALSE
```

#### Frida Intercepter - monitor file open

```
// frida -U -l open.js --no-pause -f com.yd.demoapp

// the below javascript code is the contents of open.js

var targetFunction = Module.findExportByName("libsystem_kernel.dylib", "open");

Interceptor.attach(targetFunction, {
    onEnter: function (args) {
        const path = Memory.readUtf8String(this.context.x0);
        console.log("[+] " + path)
    }
});
```

## Frida-Trace

`frida-trace --v`																	Check it works
`frida-trace --help`																Excellent place to read about Flags
`frida-trace -f objc_playground`													Spawn and NO trace
`frida-trace -m "+[NSUUID UUID]" -U "Debug CrackMe"`								Trace ObjC UUID static Class Method
`frida-trace -m "*[ComVendorDebugger* *]" -U -f com.robot.demo.app`					ObjC wildcard trace on Classes
`frida-trace -m "*[YDDummyApp.UserProfileMngr *]" -U -f com.robot.demo.app`			Trace mangled Swift functions
`frida-trace -i "getaddrinfo" -i "SSLSetSessionOption" -U -f com.robot.demo`		Trace C function on iOS
`frida-trace -m "*[*URLProtection* *]" -U -f com.robot.demo`						For https challenge information
`frida-trace -m "*[NSURLSession* *didReceiveChallenge*]" -U -f com.robot.demo`		Check whether https check delegate used
`frida-trace -U -f com.robot.demo.app -I libsystem_c.dylib`							Trace entire Module.
`frida-trace -p $myapp -I UIKit`													Trace UIKit Module.
`frida-trace -f objc_playground -I CoreFoundation`									Trace CoreFoundation Module.
`frida-trace -I YDRustyKit -U -f com.yd.mobile`										Trace my own module.
`frida-trace -m "-[NSURLRequest initWithURL:]" -U -f com.robot.demo`				Get app files and APIs
`frida-trace -m "-[NSURL initWithString:]" -U -f com.robot.demo`					Find the API endpoints
`frida-trace -m "*[NSURL absoluteString]" -U -f com.robot.demo`						My favorite of these

#### Frida-Trace strcpy()

```
frida-trace -i "*strcpy" -f hitme aaaa bbbb
Instrumenting functions...                                              
_platform_strcpy: Loaded handler at "/.../__handlers__/libSystem.B.dylib/_platform_strcpy.js"
Started tracing 1 function. Press Ctrl+C to stop.                       
```

Edit the auto-generated, template Javascript file.

```
-----------
onEnter: function (log, args, state) {
  // strcpy()  arg1 is the Source. arg0 is the Destination.
  console.log('\n[+] _platform_strcpy()');
  var src_ptr  = args[1].toString()
  var src_string = Memory.readCString(args[1]);
  var src_byte_array = Memory.readByteArray(args[1],4);
  var textDecoder = new TextDecoder("utf-8");
  var decoded = textDecoder.decode(src_byte_array);
  console.log('[+] src_ptr\t-> ' , src_ptr);
  console.log('[+] src_string\t-> ' + src_string);
  console.log('[+] src_byte_array\t-> ' + src_byte_array);
  console.log('[+] src_byte_array size\t-> ' + src_byte_array.byteLength);
  console.log('[+] src_byte_array decoded\t-> ' + decoded);
},
```

The results:

```
[+] _platform_strcpy()
[+] src_ptr	->  0x7ffeefbffaa6
[+] src_string	-> aaaa
[+] src_byte_array	-> [object ArrayBuffer]
[+] src_byte_array size	-> 4
[+] decoded	-> aaaa

[+] _platform_strcpy()
[+] src_ptr	->  0x7ffeefbffaab
[+] src_string	-> bbbb
[+] src_byte_array	-> [object ArrayBuffer]
[+] src_byte_array size	-> 4
[+] decoded	-> bbbb
```

#### Frida Objective-C Observer

```
frida-ps -Uai  // get your bundle ID

frida --codeshare mrmacete/objc-method-observer -U -f funky-chicken.push-demo

[+] At the Frida prompt...

observeSomething('*[ABC* *]'); // any Class beginning with ABC, regardless of instance or static class
observeSomething('-[WKWebsiteDataStore httpCookieStore]');
observeSomething('-[WKWebAllowDenyPolicyListener *]');
observeSomething('-[WKWebView loadRequest:]');                // dump the URL to hit
observeSomething('-[WKWebView load*]');                       // you get all HTML, js, css, etc
observeSomething('-[WKWebView loadHTMLString:baseURL:]')      // really effective; see the entire request
observeSomething('-[WKWebView *Agent]');                      // try to see if somebody set a custom UserAgent
observeSomething('*[* isEqualToString*]');                    // watch string compares
```

## Bypass anti-Frida checks

#### Rename Frida process

`bash -c "exec -a YDFooBar ./frida-server &"`

#### Set Frida-Server on host to a specific interface and port

`frida-server -l 0.0.0.0:19999 &`

#### Call Frida-server from Host

`frida-ps -ai -H 192.168.0.38:19999`

#### Trace on custom port

`frida-trace -m "*[NSURLSession* *didReceiveChallenge*]" -H 192.168.0.38:19999 -f com.youdog.rusty.tinyDormant`

## Objection

Objection is a runtime mobile exploration toolkit powered by Frida to assess the security posture of mobile applications **without needing to write scripts**.

### Install objection

`pip3 install objection`  

### objection:

`objection device_type`			Get information about an attached device  
`objection explore`				Start the objection exploration REPL  
`objection explore --startup-command 'ios jailbreak simulate'`  
`objection explore --startup-command 'ios jailbreak disable'`  
								Early Instrumentation  

### objection explore:

`ls`  
`env` 								This will print out the locations of the applications Library, Caches and Documents directories  
`!<shell command>`					Run OS command  
`file download <remote path> [<local path>]`    
`file upload <local path> [<remote path>]`   
									Upload/Download  
`file cat <file>`					View file  
`memory dump all <local destination>`
`memory dump from_base <base_address> <size_to_dump> <local_destination>`  
									Dump all memory/Dump part  
`memory list modules`				List loaded modules in memory  
`memory list exports <module_name>`	Exports of a loaded module  
`memory search "<pattern eg: 41 41 41 ?? 41>" (--string) (--offsets-only)`  
`memory write "<address>" "<pattern eg: 41 41 41 41>" (--string)`  
									Search/Write  
`sqlite connect pewpew.sqlite`		Query the sqlite database  
`sqlite execute schema` 			Have a look at the table structure  
`sqlite execute query select * from data;`  
									Execute any query  
`import <local path frida-script>`	Import frida script  
`jobs list`							List running scripts/jobs  
`jobs kill <job id>`				Kill script/job  
`ios plist cat credentials.plist`	Read plist file  
`ios info binary`					Inspect binary info  
`ios sslpinning disable --quiet`	Disable SSL pinning  
`ios jailbreak simulate`			Simulate a jailbroken environment to understand how an application behaves  
`ios jailbreak disable`				Jailbreak detection bypass  
`ios nsuserdefaults get` 			Dump NSUserDefaults  
`ios nsurlcredentialstorage dump`	Dump NSURLCredentialStorage  
`ios keychain dump` 				Dump app keychain  
`ios cookies get`					Get secure flags and sensitive data stored in cookies  
`ios monitor crypto monitor`		Hooks CommonCrypto to output information about cryptographic operation  
`ios ui dump`						Dump UI hierarchy  
`ios ui alert "<message>"`			Show alert  

### objection hooking:

`env`								Local app paths  
`ios bundles list_bundles`			List bundles of the application  
`ios bundles list_frameworks`		List external frameworks used by the application  
`ios hooking list classes` 			List classes of the app  
`ios hooking search classes <str>` 	Search a class that contains a string  
`ios hooking list class_methods`	List methods of a specific class  
`ios hooking search methods <str>`	Search a method that contains a string  
`ios hooking watch class <class_name>`  
									Hook all the methods of a class, dump all the initial parameters and returns  
`ios hooking watch method "-[<class_name> <method_name>]" --dump-args --dump-return --dump-backtrace`  
									Hook an specific method of a class dumping the parameters, backtraces and returns  
`ios hooking set return_value "-[<class_name> <method_name>]" false`  
									This will make the selected method return the indicated boolean  
`ios hooking generate simple <class_name>`  
									Generate hooking template.  

## r2frida

### **Attach**

`r2 frida://device-id/Snapchat`						Attach to a running app using the display name.  
`r2 frida://attach/usb//Gadget`						Attach to the Frida Gadget  

### **Spawn**

`r2 frida://device-id//com.snapchat.android`		Spawn an app using two `//` and the package name.  
`r2 frida://spawn/usb/device-id/com.android.app`	Or explicitly using the word `spawn`  
`r2 frida://spawn/usb//com.android.app`				Or without entering the `device-id`  

### Commands

`=!?`							Get the list of commands  
  
`=!?~^i`:  
`i`								Show target information  
`ii[*]`							List imports  
`il`							List libraries  
`is[*] <lib>`					List symbols of lib (local and global ones)  
`iE[*] <lib>`					Same as is, but only for the export global ones  
`iEa[*] (<lib>) <sym>`			Show address of export symbol  
`isa[*] (<lib>) <sym>`			Show address of symbol  
`ic <class>`					List Objective-C classes or methods of \<class>  
`ip <protocol>`					List Objective-C protocols or methods of \<protocol>  
`=!i`							Shows target information  
`=!i*`							Shows target information in r2 form  
`.=!i*`							Radare2 imports all the dynamic binary data from Frida. E.g: which architecture, endianness, pointer size, etc...  
`.=!iE*`						Radare2 imports all the dynamic `export` data from Frida for all the dynamic libraries.  
`.=!iE* <lib>`					Radare2 imports all the dynamic `export` data from Frida for only one specific library.  
`.=!ii*`						Radare2 imports all the dynamic `import` data from Frida.  
`=!ii <lib>`					List imports. Commonly used with the symbol `~`, which is the internal grep of `r2`.  
`=!ii* <lib>`					List imports in r2 form.  
`=!il`							List libraries. Commonly used with the symbol `~`, which is the internal grep of r2.  
`=!iE <lib>`					List exports of library(ies)  
`=!iEa (<lib>) <sym>`			Show address of export symbol  
`=!iEa* (<lib>) <sym>`			Show address of export symbol in r2 format  
`=!isa[*] (<lib>) <sym>`		Show address of symbol  
`=!ic`							List classes  
`=!/ keyword`					Search hex/string pattern in memory ranges (see search.in=?)  
  
`> =!?~^/`:  
`/[x][j] <string|hexpairs>`		Search hex/string pattern in memory ranges (see search.in=?)  
`/w[j] string`					Search wide string  
`/v[1248][j] value`				Search for a value honoring `e cfg.bigendian` of given width  

`> =!?~^d`:  
`db (<addr>|<sym>)`				List or place breakpoint  
`db- (<addr>|<sym>)|*`			Remove breakpoint(s)  
`dc`							Continue breakpoints or resume a spawned process  
`dd[-][fd] ([newfd])`			List, dup2 or close filedescriptors  
`dm[.|j|*]`						Show memory regions  
`dma <size>`					Allocate <size> bytes on the heap, address is returned  
`dmas <string>`					Allocate a string inited with <string> on the heap  
`dmad <addr> <size>`			Allocate <size> bytes on the heap, copy contents from <addr>  
`dmal`							List live heap allocations created with dma[s]  
`dma- (<addr>...)`				Kill the allocations at <addr> (or all of them without param)  
`dmp <addr> <size> <perms>`		Change page at <address> with <size>, protection <perms> (rwx)  
`dmm`							List all named squashed maps  
`dmh`							List all heap allocated chunks  
`dmhj`							List all heap allocated chunks in JSON  
`dmh*`							Export heap chunks and regions as r2 flags  
`dmhm`							Show which maps are used to allocate heap chunks  
`dp`							Show current pid  
`dpt`							Show threads  
`dr`							Show thread registers (see dpt)  
`dl libname`					Dlopen a library  
`dl2 libname [main]`			Inject library using Frida's >= 8.2 new API  
`dt (<addr>|<sym>) ...`			Trace list of addresses or symbols  
`dth (<addr>|<sym>) (x y..)`	Define function header (z=str,i=int,v=hex barray,s=barray)  
`dt-`							Clear all tracing  
`dtr <addr> (<regs>...)`		Trace register values  
`dtf <addr> [fmt]`				Trace address with format (^ixzO) (see dtf?)  
`dtSf[*j] [sym|addr]`			Trace address or symbol using the stalker (Frida >= 10.3.13)  
`dtS[*j] seconds`				Trace all threads for given seconds using the stalker  
`di[0,1,-1] [addr]`				Intercept and replace return value of address  
`dx [hexpairs]`					Inject code and execute it (TODO)  
`dxc [sym|addr] [args..]`		Call the target symbol with given args  
  
`e[?] [a[=b]]`					List/get/set config evaluable vars  
  
```bash
[0x00000000]> =!e
e patch.code=true
e search.in=perm:r--
e search.quiet=false
e stalker.event=compile
e stalker.timeout=300
e stalker.in=raw  
```

`=!. script.js`  
`=!ic`						List iOS classes  

More info:
[https://mobile-security.gitbook.io/mobile-security-testing-guide/ios-testing-guide/0x06c-reverse-engineering-and-tampering#tampering-and-runtime-instrumentation](https://mobile-security.gitbook.io/mobile-security-testing-guide/ios-testing-guide/0x06c-reverse-engineering-and-tampering#tampering-and-runtime-instrumentation)

## Grapefruit (Passionfruit)

Frida GUI.

## Dwarf

Frida GUI.

## Fermion

Frida GUI. [https://github.com/FuzzySecurity/Fermion](https://github.com/FuzzySecurity/Fermion)

More info:  
[https://frida.re/docs/examples/ios/](https://frida.re/docs/examples/ios/)  
[https://frida.re/docs/frida-trace/ ](https://frida.re/docs/frida-trace/)  
https://frida.re/docs/examples/ios/  
[https://github.com/sensepost/objection/wiki/Using-objection](https://github.com/sensepost/objection/wiki/Using-objection)  
Apple's Entitlements Troubleshooting – [https://developer.apple.com/library/content/technotes/tn2415/_index.html](https://developer.apple.com/library/content/technotes/tn2415/\_index.html)  
Apple's Code Signing – [https://developer.apple.com/support/code-signing/](https://developer.apple.com/support/code-signing/)  
Cycript Manual – [http://www.cycript.org/manual/](http://www.cycript.org/manual/)  
Frida iOS Tutorial – [https://www.frida.re/docs/ios/](https://www.frida.re/docs/ios/)  
Frida iOS Examples – [https://www.frida.re/docs/examples/ios/](https://www.frida.re/docs/examples/ios/)  
r2frida Wiki – [https://github.com/enovella/r2frida-wiki/blob/master/README.md](https://github.com/enovella/r2frida-wiki/blob/master/README.md)  
Charlie Miller, Dino Dai Zovi. The iOS Hacker's Handbook. Wiley, 2012 – [https://www.wiley.com/en-us/iOS+Hacker's+Handbook-p-9781118204122](https://www.wiley.com/en-us/iOS+Hacker%27s+Handbook-p-9781118204122)  
Jonathan Levin. Mac OS X and iOS Internals: To the Apple's Core. Wiley, 2013 – [http://newosxbook.com/MOXiI.pdf](http://newosxbook.com/MOXiI.pdf)  

# Analyze application network traffic

## Disabling SSL pinning

Install SSL Kill Switch 2 from [https://github.com/nabla-c0d3/ssl-kill-switch2/releases/](https://github.com/nabla-c0d3/ssl-kill-switch2/releases/)

Open your settings and enable SSL Kill Switch 2

## Intercepting with Charles Proxy

<div align="center"><img src="https://ia601403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/_xbjsbi2ehcuk3fwbbeoaw9lsr8.png" alt=""  width="480px" /></div>

1. Run Charles on PC.

2. Install Charles Root Certificate on iOS device:

<div align="center">

Help → SSL Proxing → Install Charles Root Certificate on Mobile Device or Remote Browser.  

<img src="https://ia801403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/eetlvlctkstxbxa0uld6b6nbwvk.png" width="960px">

</div>

The following window will appear:

<div align="center"><img src="https://ia601403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/70o50ggj92kd8t_fjxo-a--uh3e.png" alt=""  width="720px" /></div>

3. In the network settings of the iOS device specify the IP and port of Charles Proxy:

<div align="center"><img src="https://ia601403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/0eq3ozbi5czwwi7sgpzu_j8nfg8.png" alt=""   width="336px" /></div>

Depending on your network architecture the IP address Charles is running on may differ.

4. Open the browser on the iOS device and follow the link — [http://chls.pro/ssl](http://chls.pro/ssl)

<div align="center"><img src="https://ia601403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/mc_6ol45uh4yrwixs0b0p0ko9xm.png" alt=""  width="336px" /></div>

5. Install Charles SSL certificate on the device:

<div align="center"><img src="https://ia801403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/km0p9-zasxuckzmyoqd1hgqtw2y.png" alt=""  width="336px" /></div>

6. Enable SSL Proxying

<div align="center">

Proxy → SSL Proxying Settings... → Add (Include) → Host: `*` ; Port: `*`  

<img src="https://ia601403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/Screenshot_2021-09-16_at_7.21.10_PM.png" alt=""  width="677px" />

<img src="https://ia801403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/Screenshot_2021-09-16_at_7.21.40_PM.png" alt=""  width="526px" />

</div>

7. Start SSL Proxying:

<div align="center"><img src="https://ia801403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/Screenshot_2021-09-16_at_7.22.13_PM.png" alt=""  width="288px" /></div>

# Get decrypted .ipa file

Since all binary files inside an .ipa are encrypted with AES and being decrypted with a private key by Secure Enclave Processor at the runtime there is a few ways to decrypt it:

### With Apple mobile device – Dump it with bagbak (with extensions) or frida-ios-dump (can't dump extensions) or any other tool

If you don't have Node.js:

`brew install nvm`    
`nvm install node`  

To dump decrypted ipa using bagbak utility install it on desktop:

`sudo npm install -g bagbak`  

Then download your application from the App Store and dump:

`bagbak <bundle id or name> --uuid <uuid> --output <output>`  

### With Apple mobile device – Run the hardware AES decryption

There are several ways to run the hardware AES engine:

- Patch [iBoot](https://www.theiphonewiki.com/wiki/IBoot_(Bootloader)) to jump to `aes_crypto_cmd`  
- Use [OpenIBoot](http://github.com/planetbeing/iphonelinux/tree/master)
- Use [XPwn](https://www.theiphonewiki.com/wiki/XPwn) with a kernel patch
- Use [Greenpois0n](https://www.theiphonewiki.com/wiki/Greenpois0n_(toolkit)) console:

    `ideviceenterrecovery`  
    `irecovery --shell`  
    `go aes dec <file>`  
- Use [ipwndfu](http://github.com/Axi0mX/ipwndfu)
- Use checkra1n

### We will use latest tools – checkra1n & pongoOS:

Run checkra1n with `-p` to run into pongoOS ([https://github.com/checkra1n/pongoOS](https://github.com/checkra1n/pongoOS)) and use the `aes` command over USB

# Analyze application binaries

If you want to disassemble an application from the App Store, remove the FairPlay DRM first. 

After decrypting .ipa file open app binary in disassembler like **IDA Pro**.

In this section the term "app binary" refers to the Macho-O file in the application bundle which contains the compiled code, and should not be confused with the application bundle - the IPA file.

## Tools

### Mach-O Binary Analyzers:

- MachOViewer ([Homepage](http://sourceforge.net/projects/machoview/))

### Hex Editors:

- Hex Fiend ([Homepage](http://ridiculousfish.com/hexfiend/))
- 0xED ([Homepage](http://www.suavetech.com/0xed/))
- Synalyze It! ([Homepage](http://www.synalysis.net/))

### Disassemblers:

- Hopper ([Homepage](http://www.hopperapp.com/))
- IDA ([Homepage](https://www.hex-rays.com/products/ida/index.shtml))
- otool ([man page](x-man-page://1/otool))
- otx ([Homepage](http://otx.osxninja.com/))

### Decompilers:

- Hopper ([Homepage](http://www.hopperapp.com/))
- Hex-Rays ([Homepage](https://www.hex-rays.com/products/decompiler/index.shtml))
- classdump ([Homepage](http://stevenygard.com/projects/class-dump/))
- codedump (i386) ([Source ZIP](https://pewpewthespells.com/re/i386codedump.zip))

### Debuggers:

- GDB (Not shipped on OS X anymore) ([Homepage](http://www.sourceware.org/gdb/))
- LLDB ([Homepage](http://lldb.llvm.org/) - [man page](x-man-page://1/lldb))
- PonyDebugger ([link](https://github.com/square/PonyDebugger))

### Memory Editors:

- Bit Slicer ([Homepage](http://zorg.tejat.net/programs/) - [Source](https://bitbucket.org/zorgiepoo/bit-slicer/))

### Various Command Line Tools:

- nm ([man page](x-man-page://1/nm))
- strings ([man page](x-man-page://1/strings))
- dsymutil ([man page](x-man-page://1/dsymutil))
- install_name_tool ([man page](x-man-page://1/install_name_tool))
- ld ([man page](x-man-page://1/ld))
- lipo ([man page](x-man-page://1/lipo))
- codesign ([man page](x-man-page://1/codesign))
- hexdump ([man page](x-man-page://1/hexdump))
- dyld_shared_cache ([link](x-man-page://1/hexdump))
- vbindiff ([link](http://www.cjmweb.net/vbindiff/))
- binwalk ([link](https://code.google.com/p/binwalk/))
- xpwntool ([link](http://theiphonewiki.com/wiki/Xpwntool))
- objdump ([link](https://sourceware.org/binutils/docs/binutils/objdump.html))

## Disassembling with IDA Pro

If you have a license for IDA Pro, you can analyze the app binary using IDA Pro as well.

To get started, simply open the app binary in IDA Pro.

<div align="center"><img src="https://ia601403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/ida_macho_import.png" alt=""  width="768px" /></div>

Upon opening the file, IDA Pro will perform auto-analysis, which can take a while depending on the size of the binary. Once the auto-analysis is completed you can browse the disassembly in the **IDA View** (Disassembly) window and explore functions in the **Functions** window, both shown in the screenshot below.

<div align="center"><img src="https://ia801403.us.archive.org/18/items/8-e-269-ece-3-a-71-4-b-12-a-460-ca-06-db-9297-b-2/ida_main_window.png"></div>

## IDA Pro plugins for iOS and Mach-O

[https://github.com/ChiChou/IDA-ObjCExplorer/blob/master/ObjCExplore.py](https://github.com/ChiChou/IDA-ObjCExplorer/blob/master/ObjCExplore.py) – Obj-C Classes Explorer for IDA Pro. Just press **Ctrl + Shift + E**.

[https://github.com/avast/retdec-idaplugin](https://github.com/avast/retdec-idaplugin) – RetDec decompiler for IDA Pro. Just press **Ctrl + D**.

[https://github.com/zynamics/objc-helper-plugin-ida](https://github.com/zynamics/objc-helper-plugin-ida) – zynamics Objective-C helper script.

[https://github.com/techbliss/Frida_For_Ida_Pro](https://github.com/techbliss/Frida_For_Ida_Pro) – Connect frida.

### Kernelcache analysis

[https://github.com/vadimszzz/idapython/blob/master/cortex_m_firmware.py](https://github.com/vadimszzz/idapython/blob/master/cortex_m_firmware.py) – IDA Python module for loading ARM Cortex M firmware.

[https://github.com/saelo/ida_scripts/blob/master/kernelcache.py](https://github.com/saelo/ida_scripts/blob/master/kernelcache.py) – Identify and rename function stubs in an iOS kernelcache.

[https://github.com/luismiras/IDA-iOS-scripts/blob/master/find_iOS_syscalls.py](https://github.com/luismiras/IDA-iOS-scripts/blob/master/find_iOS_syscalls.py) – Find iOS syscalls.

[https://github.com/stefanesser/IDA-IOS-Toolkit/blob/master/listAllKEXT.py](https://github.com/stefanesser/IDA-IOS-Toolkit/blob/master/listAllKEXT.py) – List all Kexts.

[https://github.com/stefanesser/IDA-IOS-Toolkit/blob/master/findSyscallTable.py](https://github.com/stefanesser/IDA-IOS-Toolkit/blob/master/findSyscallTable.py) – This script searches the iOS syscall table within the iOS kernelcache.

[https://github.com/stefanesser/IDA-IOS-Toolkit/blob/master/fixupSysctlSet.py](https://github.com/stefanesser/IDA-IOS-Toolkit/blob/master/fixupSysctlSet.py) – This script ensures that all sysctl_oid structures referenced by the sysctl_set segment are marked correctly.

[https://github.com/bazad/ida_kernelcache](https://github.com/bazad/ida_kernelcache) – An IDA Toolkit for analyzing iOS kernelcaches.

### Get information about methods

You can use [class-dump](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x08-Testing-Tools.md#class-dump) to get information about methods in the application's source code. 

Note the architectures: `armv7` (which is 32-bit) and `arm64`. This design of a fat binary allows an application to be deployed on all devices. To analyze the application with class-dump, we must create a so-called thin binary, which contains one architecture only:

```  
iOS8-jailbreak:~ root# lipo -thin armv7 DamnVulnerableIOSApp -output DVIA32  
```

And then we can proceed to performing class-dump:

```bash
iOS8-jailbreak:~ root# class-dump DVIA32

@interface FlurryUtil : ./DVIA/DVIA/DamnVulnerableIOSApp/DamnVulnerableIOSApp/YapDatabase/Extensions/Views/Internal/
{
}
+ (BOOL)appIsCracked;
+ (BOOL)deviceIsJailbroken;  
```

Note the plus sign, which means that this is a class method that returns a BOOL type. A minus sign would mean that this is an instance method. Refer to later sections to understand the practical difference between these.

### Retrieving  Symbols and Strings

Strings are always a good starting point while analyzing a binary, as they provide context to the associated code. For instance, an error log string such as "Cryptogram generation failed" gives us a hint that the adjoining code might be responsible for the generation of a cryptogram.

In order to extract strings from an iOS binary, you can use GUI tools such as Ghidra or Cutter or rely on CLI-based tools such as the *strings* Unix utility `strings <path_to_binary>` or radare2's rabin2 `rabin2 -zz <path_to_binary>`. When using the CLI-based ones you can take advantage of other tools such as grep (e.g. in conjunction with regular expressions) to further filter and analyze the results.

#### Symbols

**nm**

```
nm libprogressbar.a | less
```

**rabin2**

```
rabin2 -s file
```

**radare2**

```
is~FUNC
```

#### Strings

Check URLs:

```
strings <binary inside app bundle>  | grep -E 'session|https'
strings <binary inside app bundle>  | grep -E 'pinning'
rabin2 -qz <binary inside app bundle>                                   // in Data Section
rabin2 -qzz <binary inside app bundle>                                  // ALL strings in binary

jtool -dA __TEXT.__cstring c_playground
Dumping C-Strings from address 0x100000f7c (Segment: __TEXT.__cstring)..
Address : 0x100000f7c = Offset 0xf7c
0x100000f7c: and we have a winner @ %ld\r
0x100000f98: and that's a wrap folks!\r
```

### Cross References

IDA Pro can be used for obtaining cross references by right clicking the desired function and selecting **Show xrefs**.

# ARM64 assembly

### Registers

-   General purpose registers 0 through 30 with two addressing modes:
    -   `w0` = 32-bit
    -   `x0` = 64-bit
-   Zero register `wzr` or `xzr`. Write to = discard, read from = `0`.
-   Stack pointer `sp` - unlike other instruction sets, never modified implicitly (e.g. no `push`/`pop`).
-   Instruction pointer `pc`, not modifiable directly.
-   A lot of float, vector and system registers, look up as needed.
-   First register in assembly is usually destination, rest are source (except for `str`).

### Register manipulation

-   `mov` to copy one register to another, e.g. `mov x0, x1` -> `x0 = x1`.
-   Constant `0` loaded from `wzr`/`xzr`.
-   Small constants usually OR'ed with zero register, e.g. `orr x0, xzr, 5`.
-   Big constants usually loaded with `movz`+`movk`, e.g.:
    ```asm
    movz x0, 0x1234, lsl 32
    movk x0, 0x5678, lsl 16
    movk x0, 0x9abc
    ```
    -> `x0 = 0x123456789abc`.
-   `movn` for negative values, e.g. `movn x0, 1` -> `x0 = -1`.
-   `lsl` and `lsr` instructions = logic-shift-left and logic-shift-right, e.g. `lsl x0, x0, 8` -> `x0 <<= 8`.
    -   `lsl` and `lsr` not only used as instructions, but also as operands to other instructions (see `movz` above).
    -   `asl` for arithmetic shift also exists, but less frequently used.
-   Lots of arithmetic, logic and bitwise instructions, look up as needed.

### Memory

-   `ldr` and `str` with multiple variations and addressing modes:
    -   `ldr x0, [x1]` -> `x0 = *x1`
    -   `str x0, [x1]` -> `*x1 = x0`
    -   `ldr x0, [x1, 0x10]` -> `x0 = *(x1 + 0x10)`
    -   `ldp`/`stp` to load/store two registers at once behind each other, e.g.:  
        `stp x0, x1, [x2]` -> `*x2 = x0; *(x2 + 8) = x1;`
    -   Multiple variations for load/store size:
        -   Register names `xN` for 64-bit, `wN` for 32-bit
        -   `ldrh`/`srth` for 16-bit
        -   `ldrb`/`strb` for  8-bit
    -   Multiple variations for sign-extending registers smaller than 64-bit:
        -   `ldrsw x0, [x1]` -> load 32-bit int, sign extend to 64-bit
        -   `ldrsh x0, [x1]` -> load 16-bit int, sign extend to 64-bit
        -   `ldrsb x0, [x1]` -> load  8-bit int, sign extend to 64-bit
        -   (No equivalent `str` instructions)
-   Three register addressing modes:
    -   Normal: `ldr x0, [x1, 0x10]`
    -   Pre-indexing: `ldr x0, [x1, 0x10]!` (notice the `!`) -> `x1 += 0x10; x0 = *x1;`
    -   Post-indexing: `ldr x0, [x1], 0x10` -> `x0 = *x1; x1 += 0x10;`
-   Memory addresses usually computed by PC-relative instructions:
    -   `adr x0, 0x12345` (only works for small offset from PC)
    -   Bigger ranges use `adrp`+`add`:
        ```asm
        adrp x0, 0xffffff8012345000 ; "address of page", last 12 bits are always zero
        add x0, x0, 0x678
        ```
    -   Even bigger ranges usually stored as pointers in data segment, offset by linker and loaded with `ldr`.

### Calling convention

_Note: Only dealing with integral types here. The rules change when floating-point is involved._

-   `x0`-`x7` first 8 arguments, rest on the stack (low address to high) with natural alignment (as if they were members of a struct)
-   `x8` pointer to where to write the return value if >128 bits, otherwise scratch register
-   `x9`-`x17` scratch registers
-   `x18` platform register (reserved, periodically zeroed by XNU)
-   `x19`-`x28` callee-saved
-   `x29` frame pointer (basically also just callee-saved)
-   `x30` return address
-   Functions that save anything in `x19`-`x28` usually start like this:
    ```asm
    stp x24, x23, [sp, -0x40]!
    stp x22, x21, [sp, 0x10]
    stp x20, x19, [sp, 0x20]
    stp x29, x30, [sp, 0x30]
    add x29, sp, 0x30
    ```
    and end like this:
    ```asm
    ldp x29, x30, [sp, 0x30]
    ldp x20, x19, [sp, 0x20]
    ldp x22, x21, [sp, 0x10]
    ldp x24, x23, [sp], 0x40
    ret
    ```
    The stack for local variables is usually managed separately though, with `add sp, sp, 0x...` and `sub sp, sp, 0x...`.
-   Variadic arguments are passed on the stack (low address to high), each promoted to 8 bytes. Structs that don't fit into 8 bytes have a pointer passed instead.  
    Fixed arguments that don't fit into `x0`-`x7` come before variadic arguments on the stack, naturally aligned.
-   The return value is passed as follows:
    -   If it fits into 64 bits, in `x0`.
    -   If it fits into 128 bits, the first/lower half in `x0`, the second/upper half in `x1`.
    -   If it is larger than 128 bits, the caller passes a pointer in `x8` to where the result is written.

### Conditions

-   System register `nzcv` holds condition flags (Negative, Zero, Carry, oVerflow).  
    Set by one instruction and acted upon by a subsequent one, the latter using condition codes.  
    (Could be accessed as normal system register, but usually isn't.)
-   Some instructions use condition codes as suffixes (`instr.cond`), others as source operands (`instr ..., cond`). List of condition codes:
    -   `eq`/`ne` = equal/not equal
    -   `lt`/`le`/`gt`/`ge` = less than/less or equal/greater than/greater or equal (signed)
    -   `lo`/`ls`/`hi`/`hs` = lower/lower or same/higher/higher or same (unsigned)
    -   A few more weird flags, seldom used.
    -   Unlike many other instruction sets, arm64 sets carry on no-borrow rather than borrow.  
        Thus, `cs`/`cc` = carry set/carry clear are aliases of `hs`/`lo`.
-   `cmp` = most common/basic compare instruction, sets condition flags. Examples:
    ```asm
    cmp x0, x1
    cmp x0, 3
    ```
-   Other instructions that set condition flags:
    -   `cmn` = compare negative
    -   `tst` = bitwise test
    -   `adds`/`adcs` = add/add with carry
    -   `subs`/`sbcs` = subtract/subtract with carry
    -   `negs`/`ngcs` = negate/negate with carry
    -   Some more bitwise and float instructions.
-   Some instructions that act on condition flags:
    -   `cset` = conditional set, e.g.:
        ```asm
        cmp x0, 3
        cset x0, lo
        ```
        -> `x0 = (x0 < 3)`
    -   `csel` = conditional select, e.g.:
        ```asm
        cmp x0, 3
        csel x0, x1, x2, lo
        ```
        -> `x0 = (x0 < 3) ? x1 : x2`  
        (Translates nicely to ternary conditional.)
    -   `ccmp` = conditional compare, e.g.:
        ```asm
        cmp x0, 3
        ccmp x0, 7, 2, hs
        b.hi 0xffffff8012345678
        ```
        -> `hi` condition will be true if `x0 < 3 || x0 > 7` (third `ccmp` operand is raw `nzcv` data).  
        Often generated by compiler for logical and/or of two conditions.
    -   Many, many more.

### Branches

-   `b` = simple branch, jump to PC-relative address.  
    Can be unconditional:
    ```asm
    b 0xffffff8012345678
    ```
    or conditional:
    ```asm
    cmp x0, 3
    b.lo 0xffffff8012345678 ; jump to 0xffffff8012345678 if x < 3
    ```
    Used primarily within function for flow control.
-   Shortcuts `cbz`/`cbnz` = compare-branch-zero and compare-branch-non-zero.  
    Just shorter ways to write
    ```asm
    cmp xN, 0
    b.eq 0x...
    ```
    or
    ```asm
    cmp xN, 0
    b.ne 0x...
    ```
    (Translate nicely to C `if(x)` or `if(!x)`.)
-   Shortcuts `tbz`/`tbnz` = test single bit and branch if zero/non-zero.  
    E.g. `tbz x0, 3, ...` translates to `if((x0 & (1 << 3)) == 0) goto ...`.
-   `bl` = branch-and-link (e.g. `bl 0xffffff8012345678`)  
    Store return address to `x30` and jump to PC-relative address. Used for static function calls.
-   `blr` = branch-and-link to register (e.g. `blr x8`)  
    Store return address to `x30` and jump to address in `x8`. Used for calls with function pointers or C++ virtual methods.
-   `br` = branch to register (e.g. `br x8`)  
    Jump to address in `x8`. Used for tail calls.
-   `ret` = return to address in register, default: `x30`  
    Can in theory use registers other than `x30` (e.g. `ret x8`), but compiler doesn't usually generate that.
### Miscellaneous

-   `nop` = do nothing
-   `svc` = make a system call using an immediate value (e.g. `svc 0x80`). Note that the immediate value is separate from the syscall number. XNU ignores the immediate and expects the syscall number in `x16`.
-   `.` = special symbol that refers to the address of the instruction it is used in (e.g. `adr x0, .`)

# iOS tweak development

## Theos

### Installation instructions for macOS

1. Install the following prerequisites:

   - [Homebrew](https://brew.sh/)
   - [Xcode](https://itunes.apple.com/us/app/xcode/id497799835?ls=1&mt=12) is mandatory. The Command Line Tools package isn’t sufficient for Theos to work. Xcode includes toolchains for all Apple platforms.

   ```
    brew install ldid xz
   ```
   
2. Set up the `THEOS` environment variable:

   ```
    echo "export THEOS=~/theos" >> ~/.zshrc
    source ~/.zshrc
   ```
   
3. Clone Theos:

   ```
    git clone --recursive https://github.com/theos/theos.git $THEOS
   ```

4. Get the toolchain:

   Xcode contains the toolchain.

5. Get an iOS SDK:

   Xcode always provides the latest iOS SDK, but as of Xcode 7.3, it no longer includes private frameworks you can link against. This may be an issue when developing tweaks. You can get patched SDKs from [our SDKs repo](https://github.com/theos/sdks).

   ```
    curl -LO https://github.com/theos/sdks/archive/master.zip
    TMP=$(mktemp -d)
    unzip master.zip -d $TMP
    mv $TMP/sdks-master/*.sdk $THEOS/sdks
    rm -r master.zip $TMP
   ```

## Logos

Logos is a Perl regex-based preprocessor that simplifies the boilerplate code needed to create hooks for Objective-C methods and C functions with an elegant Objective-C-like syntax. It’s most commonly used along with the Theos build system, which was originally developed to create jailbreak tweaks. Logos was once integrated in the same Git repo as Theos, but now has been decoupled from Theos to its own repo.

Logos aims to provide an interface for [Cydia Substrate](https://cydiasubstrate.com/) by default, but can be configured to directly use the Objective-C runtime.

Logos is a component of the [Theos](https://theos.dev/) development suite.

```
%hookf(return type, functionName, arguments list...) {
	/* body */
}
```

Generate a function hook for the function named `functionName`. Set `functionName` in `%init` to an expression if the symbol should be dynamically looked up.

Example:

```
// Given the function prototype (only add it yourself if it's not declared in an included/imported header)

FILE *fopen(const char *path, const char *mode);

// The hook is thus made
%hookf(FILE *, fopen, const char *path, const char *mode) {
	puts("Hey, we're hooking fopen to deny relative paths!");
	if (path[0] != '/') {
		return NULL;
	}
	return %orig; // Call the original implementation of this function
}

// functions can also be looked up at runtime, if, for example, the function is in a private framework
%hookf(BOOL, MGGetBoolAnswer, CFStringRef string) {
	if (CFEqual(string, CFSTR("StarkCapability"))) {
		return YES;
	}
	return %orig;
}
%ctor() {
	%init(MGGetBoolAnswer = MSFindSymbol(NULL, "_MGGetBoolAnswer"));
}
```

### %ctor

```
%ctor {
	/* body */
}
```

Generate an anonymous constructor (of default priority). This function is executed after the binary is loaded into memory. `argc`, `argv`, and `envp` are implicit arguments so they can be used as they would be in a `main` function.

### %dtor

```
%dtor {
	/* body */
}
```

Generate an anonymous deconstructor (of default priority). This function is executed before the binary is unloaded from memory.`argc`, `argv`, and `envp` are implicit arguments so they can be used as they would be in a `main` function.

## Block level

The directives in this category open a block of code which must be closed by an [%end](https://theos.dev/docs/logos-syntax#end) directive (shown below). These should not exist within functions or methods.

### %group

```
%group GroupName
/* %hooks */
%end
```

Generate a hook group with the name `GroupName`. Groups can be used for conditional initialization or code organization. All ungrouped hooks are in the default group, initializable via [%init](https://theos.dev/docs/logos-syntax#init) without arguments.

Cannot be inside another [%group](https://theos.dev/docs/logos-syntax#group) block.

Grouping can be used to manage backwards compatibility with older code.

Example:

```
%group iOS8
%hook IOS8_SPECIFIC_CLASS
	// your code here
%end // end hook
%end // end group ios8

%group iOS9
%hook IOS9_SPECIFIC_CLASS
	// your code here
%end // end hook
%end // end group ios9

%ctor {
	if (kCFCoreFoundationVersionNumber > 1200) {
		%init(iOS9);
	} else {
		%init(iOS8);
	}
}
```

### %hook

```
%hook ClassName
/* objc methods */
%end
```

Open a hook block for the class named `ClassName`.

Can be inside a [%group](https://theos.dev/docs/logos-syntax#group) block.

Example:

```
%hook SBApplicationController
- (void)uninstallApplication:(SBApplication *)application {
	NSLog(@"Hey, we're hooking uninstallApplication:!");
	%orig; // Call the original implementation of this method
}
%end
```

### %new

```
%new
/* objc method */
%new(signature)
/* objc method */
```

Add a new method to a hooked class or subclass by adding this directive above the method definition. signature is the Objective-C type encoding for the new method; if it is omitted, one will be generated.

Must be inside a [%hook](https://theos.dev/docs/logos-syntax#hook) or [%subclass](https://theos.dev/docs/logos-syntax#subclass) block.

Example:

```
%new
- (void)handleTapGesture:(UITapGestureRecognizer *)gestureRecognizer {
	NSLog(@"Recieved tap: %@", gestureRecognizer);
}
```

### %subclass

```
%subclass ClassName: Superclass <Protocol list>
/* %properties and methods */
%end
```

Generate a subclass at runtime. Like @property in normal Objective-C classes, you can use [%property](https://theos.dev/docs/logos-syntax#property) to add properties to the subclass. The [%new](https://theos.dev/docs/logos-syntax#new) specifier is needed for a method that doesn’t exist in the superclass. To instantiate an object of the new class, you can use the [%c](https://theos.dev/docs/logos-syntax#c) operator.

Can be inside a [%group](https://theos.dev/docs/logos-syntax#group) block.

Example:

```
// An interface is required to be able to call methods of the runtime subclass using block syntax.
@interface MyObject : NSObject
@property (nonatomic, retain) NSString * someValue;
@end

%subclass MyObject : NSObject

%property (nonatomic, retain) NSString * someValue;

- (instancetype)init {
	if ((self = %orig)) {
		[self setSomeValue:@"value"];
	}
	return self;
}

%end

%ctor {
	// The runtime subclass cannot be linked at compile time so you have to use %c().
	MyObject *myObject = [[%c(MyObject) alloc] init];
	NSLog(@"myObject: %@", [myObject someValue]);
}
```

### %property

```
%property (nonatomic|assign|retain|copy|weak|strong|getter=...|setter=...) Type name;
```

Add a property to a [%subclass](https://theos.dev/docs/logos-syntax#subclass) just like you would with @property to a normal Objective-C subclass as well as adding new properties to existing classes within [%hook](https://theos.dev/docs/logos-syntax#hook).

Must be inside a [%hook](https://theos.dev/docs/logos-syntax#hook) or [%subclass](https://theos.dev/docs/logos-syntax#subclass) block.

### %end

```
%end
```

Close a [%group](https://theos.dev/docs/logos-syntax#group), [%hook](https://theos.dev/docs/logos-syntax#hook) or [%subclass](https://theos.dev/docs/logos-syntax#subclass) block.

## Function level

The directives in this category should only exist within a function or method body.

### %init

```
%init;
%init([<ClassName>=<expr>, …]);
%init(GroupName[, [+|-]<ClassName>=<expr>, …]);
```

Initialize a group’s method and function hooks. Passing no group name will initialize the default group. Passing `ClassName=expr`arguments will substitute the given expressions for those classes at initialization time. The `+` sigil (as in class methods in Objective-C) can be prepended to the classname to substitute an expression for the metaclass. If not specified, the sigil defaults to `-`, to substitute the class itself. If not specified, the metaclass is derived from the class.

The class name replacement is specially useful for classes that contain characters that can’t be used as the class name token for the [%hook](https://theos.dev/docs/logos-syntax#hook) directive, such as spaces and dots.

Example:

```
%hook ClassName
- (id)init {
	return %orig;
}
%end

%ctor {
	%init(ClassName=objc_getClass("SwiftApp.ClassName"));
}
```

### %c

```
%c([+|-]ClassName)
```

Evaluates to `ClassName` at runtime. If the `+` sigil is specified, it evaluates to MetaClass instead of Class. If not specified, the sigil defaults to `-`, evaluating to Class.

### %orig

```
%orig
%orig(args, …)
```

Call the original hooked function or method. Doesn’t work in a [%new](https://theos.dev/docs/logos-syntax#new)‘d method. Works in subclasses, strangely enough, because MobileSubstrate will generate a super-call closure at hook time. (If the hooked method doesn’t exist in the class we’re hooking, it creates a stub that just calls the superclass implementation.) `args` is passed to the original function - don’t include `self` and `_cmd`, Logos does this for you.

Example:

```
%hook ClassName
- (int)add:(int)a to:(int)b {
	if (a != 0) {
		// Return original result if `a` is not 0
		return %orig;
	}
	// Otherwise, use 1 as `a`
	return %orig(1, b);
}
%end
```

#### &%orig

```
&%orig
```

Get a pointer to the original function or method. Return type is `void (*)(id, SEL[, arg types])`

Example:

```
// Call from outside hooked method:
void (*orig_ClassName_start)(id, SEL) = nil;

void doStuff(id self, SEL _cmd) {
	if (self && orig_ClassName_start) {
		orig_ClassName_start(self, _cmd);
	}
}

%hook ClassName
- (void)start {
	%orig;
	orig_ClassName_start = &%orig;
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC),
		dispatch_get_main_queue(), ^{
			doStuff(self, _cmd);
	});
}
%end

// Call with another object:
%hook ClassName
- (int)add:(int)a to:(int)b {
	int (*_orig)(id, SEL, int, int) = &%orig;
	ClassName * myObject = [ClassName new];
	int r = _orig(myObject, _cmd, 1, 2);
	[myObject release];
	return r;
}
%end
```

Real world example at [PreferenceLoader](https://github.com/DHowett/preferenceloader/blob/master/prefs.xm#L237-L263)

### %log

```
%log;
%log([(<type>)<expr>, …]);
```

Dump the method arguments to syslog. Typed arguments included in `%log` will be logged as well.

## logify.pl

You can use logify.pl to create a Logos source file from a header file that will log all of the functions of that header file. Here is an example of a very simple Logos tweak generated by logify.pl.

Given a header file named `SSDownloadAsset.h`:

```
@interface SSDownloadAsset : NSObject
- (NSString *)finalizedPath;
- (NSString *)downloadPath;
- (NSString *)downloadFileName;
+ (id)assetWithURL:(id)url type:(int)type;
- (id)initWithURLRequest:(id)urlrequest type:(int)type;
- (id)initWithURLRequest:(id)urlrequest;
- (id)_initWithDownloadMetadata:(id)downloadMetadata type:(id)type;
@end
```

You can find logify.pl at $THEOS/bin/logify.pl and you would use it as so:

```
$THEOS/bin/logify.pl ./SSDownloadAsset.h
```

The resulting output should be:

```
%hook SSDownloadAsset
- (NSString *)finalizedPath { %log; NSString * r = %orig; NSLog(@" = %@", r); return r; }
- (NSString *)downloadPath { %log; NSString * r = %orig; NSLog(@" = %@", r); return r; }
- (NSString *)downloadFileName { %log; NSString * r = %orig; NSLog(@" = %@", r); return r; }
+ (id)assetWithURL:(id)url type:(int)type { %log; id r = %orig; NSLog(@" = %@", r); return r; }
- (id)initWithURLRequest:(id)urlrequest type:(int)type { %log; id r = %orig; NSLog(@" = %@", r); return r; }
- (id)initWithURLRequest:(id)urlrequest { %log; id r = %orig; NSLog(@" = %@", r); return r; }
- (id)_initWithDownloadMetadata:(id)downloadMetadata type:(id)type { %log; id r = %orig; NSLog(@" = %@", r); return r; }
%end
```

## Logos File Extensions

| Extension | Process order                                                |
| --------- | ------------------------------------------------------------ |
| x         | will be processed by Logos, then preprocessed and compiled as Objective-C. |
| xm        | will be processed by Logos, then preprocessed and compiled as Objective-C++. |
| xi        | will be preprocessed first, then Logos will process the result, and then it will be compiled as Objective-C. |
| xmi       | will be preprocessed first, then Logos will process the result, and then it will be compiled as Objective-C++. |

xi or xmi files enable Logos directives to be used in preprocessor macros, such as `#define`. You can also import other Logos source files with the `#include` statement. However, this is discouraged, since this leads to longer build times recompiling code that hasn’t changed. Separating into x and xm files, sharing variables and functions via `extern` declarations, is recommended.

These file extensions control how a build system such as Theos should build a Logos file. Logos itself does not take the file extension into account and works regardless of whether a file is Objective-C or Objective-C++.


### Links

[https://theos.dev/docs/](https://theos.dev/docs/)  
[https://cydia.saurik.com/faq/developing.html](https://cydia.saurik.com/faq/developing.html)  
[http://www.cydiasubstrate.com/id/7cee77bc-c4a5-4b8b-b6ef-36e7dd039692/](http://www.cydiasubstrate.com/id/7cee77bc-c4a5-4b8b-b6ef-36e7dd039692/)  
[http://www.cydiasubstrate.com/inject/](http://www.cydiasubstrate.com/inject/)  
[https://iphonedev.wiki/index.php/Cydia_Substrate](https://iphonedev.wiki/index.php/Cydia_Substrate)  
[https://cwcaude.github.io/project/tutorial/2020/07/02/iOS-tweak-dev-1.html](https://cwcaude.github.io/project/tutorial/2020/07/02/iOS-tweak-dev-1.html)  
[https://cwcaude.github.io/project/tutorial/2020/07/04/iOS-tweak-dev-2.html](https://cwcaude.github.io/project/tutorial/2020/07/04/iOS-tweak-dev-2.html)  
[https://cwcaude.github.io/project/tutorial/2020/07/12/iOS-tweak-dev-3.html](https://cwcaude.github.io/project/tutorial/2020/07/12/iOS-tweak-dev-3.html)  
[https://cwcaude.github.io/project/tutorial/2020/07/16/iOS-tweak-dev-4.html](https://cwcaude.github.io/project/tutorial/2020/07/16/iOS-tweak-dev-4.html)
