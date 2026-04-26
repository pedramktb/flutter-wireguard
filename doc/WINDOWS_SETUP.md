# Running the Windows build from a Linux host

flutter_wireguard's Windows backend uses the official `wireguard-nt` kernel
driver and `tunnel.dll`, neither of which work under Wine or MinGW. To test
locally on a Linux box you need a real Windows guest in a VM with KVM/QEMU.

## VM setup (GNOME Boxes)

1. Download a Windows 10 / 11 ISO from
   [microsoft.com/software-download](https://www.microsoft.com/software-download/).
2. Open GNOME Boxes → **+** → **Create a Virtual Machine** → select the ISO.
3. Allocate at least **4 vCPU / 8 GiB RAM / 64 GiB disk**. Smaller works but
   the Visual Studio install will be painful.
4. Boot, complete the OOBE.
5. The default `e1000` virtual NIC is fine. Wintun installs and works without
   any host-side network tweaks; if you want the guest to reach a WireGuard
   peer running on the Linux host, give the Boxes machine bridged networking
   (Settings → Devices → Network → "Bridge to LAN").

Nested virtualisation is **not** required.

## Inside the Windows guest

Run an elevated PowerShell:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
iwr https://community.chocolatey.org/install.ps1 -UseBasicParsing | iex

choco install -y git visualstudio2022buildtools cmake
choco install -y visualstudio2022-workload-vctools `
                 visualstudio2022-workload-nativedesktop
choco install -y flutter

flutter doctor                                # follow what it asks for
flutter config --enable-windows-desktop
```

Clone and run the example:

```powershell
git clone --recurse-submodules https://github.com/pedramktb/flutter-wireguard
cd flutter-wireguard\example
flutter pub get
flutter create --platforms=windows .          # one-time scaffold for example/windows
flutter run -d windows
```

> If you forgot `--recurse-submodules`, run
> `git submodule update --init --recursive` from the repo root. The
> [`third_party/wireguard-windows`](../third_party/wireguard-windows)
> submodule is only needed when rebuilding `tunnel.dll`; the prebuilt
> binary in `windows/lib/tunnel/` is enough for normal `flutter run`.

The first time you press **Start** you will get a single UAC prompt — that is
the plugin launching `flutter_wireguard_helper.exe --broker` elevated. From
then on every Start / Stop / Status flows over the user-DACL'd named pipe
without further prompts for the lifetime of the app.

## Native unit tests

The gtest suite (name validator, IPC framing) builds without a real WireGuard
peer:

```powershell
cd example
cmake -S ..\windows -B build\windows\x64\debug -A x64 `
      -Dinclude_flutter_wireguard_tests=ON
cmake --build build\windows\x64\debug --config Debug --target flutter_wireguard_test
build\windows\x64\debug\Debug\flutter_wireguard_test.exe
```

The same target runs on the `windows-latest` GitHub Actions runner — see
[.github/workflows/ci.yml](../.github/workflows/ci.yml).

## Sharing the source tree between host and guest

Easiest path: `git clone` inside the VM and push branches back. GNOME Boxes'
SPICE shared-folder support is slow on large build trees and the `.dart_tool`
churn makes it worse. If you do want host-side editing with VS Code, set up
SSH inside the guest and use the **Remote - SSH** extension; that uses
QEMU's user-mode networking out of the box.

## Why not Wine / MinGW?

* `wireguard.dll` and `tunnel.dll` ship signed and call into ring-0 driver
  IOCTLs (`wireguard-nt`); Wine does not implement those interfaces.
* Flutter Windows desktop requires the MSVC ABI (`flutter_windows.dll`,
  `flutter_wrapper_plugin`); MinGW cannot link against it.
* `CryptProtectData` (DPAPI) and `CreateService` use COM/SCM internals that
  also do not exist outside a real Windows kernel.

A real Windows guest is the only viable option.
