from __future__ import annotations

import plistlib
import re
import zipfile
from pathlib import Path

from ..binary import macho_encrypted, scan_native
from ..common import comp
from .signatures import scan_js
from ...safeio import SafeZipFile

SWIFT_MODULES = {
    "Alamofire": "github.com/Alamofire/Alamofire", "Kingfisher": "github.com/onevcat/Kingfisher",
    "SDWebImage": "github.com/SDWebImage/SDWebImage", "RxSwift": "github.com/ReactiveX/RxSwift",
    "SwiftyJSON": "github.com/SwiftyJSON/SwiftyJSON", "Moya": "github.com/Moya/Moya",
    "SnapKit": "github.com/SnapKit/SnapKit", "Realm": "github.com/realm/realm-swift",
    "Starscream": "github.com/daltoniam/Starscream", "CryptoSwift": "github.com/krzyzanowskim/CryptoSwift",
    "KeychainAccess": "github.com/kishikawakatsumi/KeychainAccess", "Lottie": "github.com/airbnb/lottie-ios",
    "NIO": "github.com/apple/swift-nio",
}


def _plist(data: bytes) -> dict:
    try:
        return plistlib.loads(data)
    except Exception:
        return {}


def _pod_name(bundle_id: str, folder: str) -> str:
    if bundle_id.startswith("org.cocoapods."):
        return bundle_id[len("org.cocoapods."):]
    return folder


def scan_ipa(path: str, target: str = "", log=None):
    comps, notes = [], []
    label = Path(path).name
    tgt = target or label

    def add(eco, name, ver, method, loc, detail="", confidence="high"):
        comps.append(comp(eco, name, ver, method, loc, detail=detail, target=tgt,
                          confidence=confidence if ver else "low"))

    with SafeZipFile(path) as zf:
        names = zf.namelist()
        app = next((n.split("/")[1] for n in names if re.match(r"^Payload/[^/]+\.app/", n)), None)
        if not app:
            raise ValueError("Payload/<Uygulama>.app bulunamadı (geçerli bir IPA değil)")
        root = f"Payload/{app}/"
        info = _plist(zf.read(root + "Info.plist")) if root + "Info.plist" in names else {}
        exe = info.get("CFBundleExecutable", app[:-4])
        if log:
            log(f"  {info.get('CFBundleIdentifier', '?')} {info.get('CFBundleShortVersionString', '?')} "
                f"({info.get('CFBundleVersion', '?')})")

        frameworks = sorted({m.group(1) for n in names
                             if (m := re.match(re.escape(root) + r"Frameworks/([^/]+\.framework)/", n))})
        is_flutter = "Flutter.framework" in frameworks
        modules: set[str] = set()
        for fw in frameworks:
            base = f"{root}Frameworks/{fw}/"
            finfo = _plist(zf.read(base + "Info.plist")) if base + "Info.plist" in names else {}
            fname = fw[:-len(".framework")]
            ver = finfo.get("CFBundleShortVersionString")
            if fname not in ("Flutter", "App") and ver and ver not in ("1.0", "1.0.0"):
                add("CocoaPods", _pod_name(finfo.get("CFBundleIdentifier", ""), fname), str(ver), "properties",
                    f"{label}!/{base}Info.plist", detail=finfo.get("CFBundleIdentifier", ""), confidence="medium")
            binp = base + finfo.get("CFBundleExecutable", fname)
            if binp in names:
                data = zf.read(binp)
                for eco, name, v, snip in scan_native(data):
                    add(eco, name, v, "binary-strings", f"{label}!/{binp}", detail=snip, confidence="medium")
                modules |= set(re.findall(rb"_TtC\d+([A-Za-z]\w+?)\d", data))
                if fname == "App" and is_flutter:
                    for p in sorted({x.decode() for x in re.findall(rb"package:([a-z0-9_]+)/", data)}
                                    - {"flutter", "flutter_test", "dart"}):
                        add("Pub", p, None, "binary-strings", f"{label}!/{binp}", detail="Dart paket URI'si")
        main_bin = root + exe
        if main_bin in names:
            data = zf.read(main_bin)
            enc = macho_encrypted(data)
            if enc:
                notes.append(("obfuscated", f"{label}!/{main_bin}",
                              "App Store FairPlay şifrelemesi: ana ikili analiz edilemedi; geliştirici IPA'sı gerekir"))
            else:
                for eco, name, v, snip in scan_native(data):
                    add(eco, name, v, "binary-strings", f"{label}!/{main_bin}", detail=snip, confidence="medium")
                modules |= set(re.findall(rb"_TtC\d+([A-Za-z]\w+?)\d", data))
        for m in sorted({x.decode() for x in modules}):
            if m in SWIFT_MODULES and not any(c.name in (m, SWIFT_MODULES[m]) for c in comps):
                add("SwiftURL", SWIFT_MODULES[m], None, "binary-strings", label, detail=f"Swift modülü {m}")
        for n in names:
            if n.startswith(root) and (n.endswith("main.jsbundle") or (n.startswith(root + "www/") and n.endswith(".js"))):
                data = zf.read(n)
                text = data.decode("utf-8", "replace") if data[:4] != b"\xc6\x1f\xbc\x03" else \
                    "\n".join(x.decode() for x in re.findall(rb"[\x20-\x7e]{5,}", data))
                for name, v, snip in scan_js(text):
                    add("npm", name, v, "signature", f"{label}!/{n}", detail=snip, confidence="medium")
                m = re.search(r"major:\s*0,\s*minor:\s*(\d+),\s*patch:\s*(\d+)", text)
                if m:
                    add("npm", "react-native", f"0.{m.group(1)}.{m.group(2)}", "signature", f"{label}!/{n}",
                        detail="ReactNativeVersion", confidence="medium")
        if is_flutter:
            notes.append(("no-osv-coverage", label,
                          "Flutter: Dart paketlerinin sürümleri derlenmiş uygulamadan okunamaz; pubspec.lock gerekir"))
        if any(c.ecosystem == "CocoaPods" for c in comps):
            notes.append(("no-osv-coverage", label, "CocoaPods bileşenleri için OSV kaydı yok (envanter / SBOM)"))
    if log:
        log(f"  {len(comps)} detections ({sum(1 for c in comps if c.version)} with version)")
    return comps, notes
