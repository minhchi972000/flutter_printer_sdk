# flutter_printer_sdk

Flutter plugin for Printer.

## Installation

Take new construction projects as an example

- New Project
```
flutter create testdemo
```
- Move the flutter_printer_sdk file to the root directory of testdemo
- In the testdemo directory, find the pubspec.yaml file
- Find 'dependencies:' and fill in the flutter_printer_sdk path

```
dependencies:
  flutter:
    sdk: flutter
  flutter_printer_sdk:
    path: flutter_printer_sdk

```
- Execute the command to make it effective
```
flutter pub get
```
- Import flutter_printer_sdk related header files in the main.dart file
```
import 'package:flutter_printer_sdk/printer_manager.dart';
import 'package:flutter_printer_sdk/pos_command.dart';

```
- Configure Android compilation environment
1. Find ./testdemo/android/app/build.gradle
2. Modify the value of minSdkVersion in defaultConfig to 21
3. Set compileSdk to 35 or higher
4. Copy flutter_printer_sdk/android/libs/printer-lib-3.2.4.aar to the current ./testdemo/android/app/libs/
5. Add implementation files ("libs/printer-lib-3.2.4.aar") to dependencies

```
android {
    compileSdk 35

    defaultConfig {
       minSdkVersion 21
    }
}

dependencies {
    implementation files("libs/printer-lib-3.2.4.aar")
}
```
- Run the project

```
flutter run
```

## Android 16KB Page Size Support

This plugin supports Android 15+ (API 35) 16KB page size requirement.

The native libraries in `printer-lib-3.2.4.aar` have been patched with 16KB page alignment. If you need to re-patch a new version of the AAR, use the included script:

```bash
python3 android/libs/patch_aar_16kb.py
# or specify a custom AAR path
python3 android/libs/patch_aar_16kb.py path/to/your.aar
```

The host app's `android/app/build.gradle` should also include:

```groovy
android {
    compileSdk 35

    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }
}
```

## What this package do

- TSPL Print: TEXT, QRcode, Barcode, Image, Image Compression, printer status check
- POS Print: TEXT, QRcode, Barcode, Image, Image Compression, printer status check, NV Print, NV Download, open cash drawer
- ZPL Print: TEXT, QRcode, Barcode, Image, Image Compression, printer status check
- Connection method: USB/Bluetooth/NET