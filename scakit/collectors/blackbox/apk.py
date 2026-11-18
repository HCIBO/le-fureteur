from __future__ import annotations

import io
import re
import struct
import zipfile
from pathlib import Path

from ..binary import scan_native
from ..common import comp
from .signatures import scan_js
from ...safeio import SafeZipFile

ECO = "Maven"

DEX_VERSION_STRINGS = [
    (re.compile(r"^okhttp/(\d+\.\d+\.\d+)"), lambda v: "com.squareup.okhttp3:okhttp" if int(v.split(".")[0]) >= 3
     else "com.squareup.okhttp:okhttp"),
    (re.compile(r"^BouncyCastle Security Provider v(\d+\.\d+(?:\.\d+)?)$"),
     lambda v: "org.bouncycastle:bcprov-jdk18on" if _ver_tuple(v) >= (1, 71) else "org.bouncycastle:bcprov-jdk15on"),
    (re.compile(r"^Apache-HttpClient/(\d+\.\d+(?:\.\d+)?)"), lambda v: "org.apache.httpcomponents:httpclient"),
    (re.compile(r"^Conscrypt/(\d+\.\d+\.\d+)"), lambda v: "org.conscrypt:conscrypt-android"),
]
DEX_PREFIXES = {
    "Lokhttp3/": "com.squareup.okhttp3:okhttp", "Lretrofit2/": "com.squareup.retrofit2:retrofit",
    "Lcom/google/gson/": "com.google.code.gson:gson", "Lcom/bumptech/glide/": "com.github.bumptech.glide:glide",
    "Lio/reactivex/rxjava3/": "io.reactivex.rxjava3:rxjava", "Lio/reactivex/": "io.reactivex.rxjava2:rxjava",
    "Lcom/fasterxml/jackson/databind/": "com.fasterxml.jackson.core:jackson-databind",
    "Lorg/bouncycastle/": "org.bouncycastle:bcprov-jdk15on", "Lnet/sqlcipher/": "net.zetetic:android-database-sqlcipher",
    "Lcom/facebook/react/": "com.facebook.react:react-native", "Lio/realm/": "io.realm:realm-android-library",
    "Lorg/apache/commons/text/": "org.apache.commons:commons-text",
    "Lorg/apache/commons/collections/": "commons-collections:commons-collections",
    "Lcom/squareup/picasso/": "com.squareup.picasso:picasso", "Lio/sentry/": "io.sentry:sentry-android",
    "Lcom/airbnb/lottie/": "com.airbnb.android:lottie", "Lorg/jsoup/": "org.jsoup:jsoup",
    "Lcom/journeyapps/barcodescanner/": "com.journeyapps:zxing-android-embedded",
}
def _ver_tuple(v: str):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def _uleb128(data: bytes, off: int):
    result = shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if b < 0x80:
            return result, off
        shift += 7


def dex_strings(data: bytes):
    if not data.startswith(b"dex\n") or len(data) < 0x70:
        return
    size, off = struct.unpack_from("<II", data, 0x38)
    for i in range(size):
        try:
            (str_off,) = struct.unpack_from("<I", data, off + i * 4)
            _, p = _uleb128(data, str_off)
            end = data.index(b"\x00", p)
            yield data[p:end].decode("utf-8", "replace")
        except (struct.error, ValueError, IndexError):
            continue


def _version_file_name(fname: str) -> str | None:
    base = fname.rsplit("/", 1)[-1][: -len(".version")]
    if "_" not in base:
        return None
    grp, _, art = base.partition("_")
    if "." in grp:
        return f"{grp}:{art}"
    if base.startswith("kotlinx_"):
        return "org.jetbrains.kotlinx:" + base.replace("_", "-")
    return None


_PROP_GROUPS = (("firebase-", "com.google.firebase"), ("play-services-", "com.google.android.gms"),
                ("transport-", "com.google.android.datatransport"))


def _strings_from_binary(data: bytes, minlen: int = 6) -> str:
    return "\n".join(m.decode("ascii", "replace") for m in re.findall(rb"[\x20-\x7e]{%d,}" % minlen, data))


PACKERS = (
    (re.compile(r"libjiagu|libjgdtc|libjgbibc"), "Qihoo 360 Jiagu"),
    (re.compile(r"libsecexe|libsecmain|libSecShell"), "Bangcle / SecNeo"),
    (re.compile(r"libDexHelper"), "SecNeo (DexHelper)"),
    (re.compile(r"libshella|libshellx|libtup"), "Tencent Legu"),
    (re.compile(r"libbaiduprotect"), "Baidu"),
    (re.compile(r"libprotectClass|libexec\.so|libexecmain"), "Ijiami"),
    (re.compile(r"libdexguard|dexguard"), "DexGuard"),
    (re.compile(r"libshield|promon"), "Promon SHIELD"),
    (re.compile(r"libloader\.so.*appdome|appdome", re.I), "Appdome"),
    (re.compile(r"libnesec|libNSaferOnly"), "NetEase"),
    (re.compile(r"liblicense_checker|libpairipcore"), "Google Play Integrity (PairIP)"),
)


class ApkScanner:
    def __init__(self, target: str, log=None):
        self.target = target
        self.log = log or (lambda m: None)
        self.comps = []
        self.notes = []
        self.unversioned: dict[str, str] = {}

    def add(self, eco, name, ver, method, loc, detail="", confidence="high"):
        self.comps.append(comp(eco, name, ver, method, loc, detail=detail, target=self.target,
                               confidence=confidence if ver else "low"))

    def scan_zip(self, zf: zipfile.ZipFile, label: str):
        names = zf.namelist()
        def strip(n):
            for pre in ("base/root/", "base/"):
                if n.startswith(pre):
                    return n[len(pre):]
            return n

        dex_files, so_files, js_files = [], [], []
        is_flutter = any(strip(n).startswith("assets/flutter_assets/") for n in names)
        for n in names:
            s = strip(n)
            loc = f"{label}!/{n}"
            if s.startswith("META-INF/maven/") and s.endswith("/pom.properties"):
                props = dict(line.split("=", 1) for line in zf.read(n).decode("utf-8", "replace").splitlines()
                             if "=" in line and not line.startswith("#"))
                if props.get("groupId") and props.get("artifactId") and props.get("version"):
                    self.add(ECO, f"{props['groupId'].strip()}:{props['artifactId'].strip()}", props["version"].strip(),
                             "jar-meta", loc)
            elif s.startswith("META-INF/") and s.endswith(".version"):
                name = _version_file_name(s)
                ver = zf.read(n).decode("utf-8", "replace").strip()
                if name and re.match(r"^\d+\.\d+", ver):
                    self.add(ECO, name, ver, "properties", loc)
            elif "/" not in s and s.endswith(".properties"):
                props = dict(line.split("=", 1) for line in zf.read(n).decode("utf-8", "replace").splitlines()
                             if "=" in line)
                client, ver = props.get("client", "").strip(), props.get("version", "").strip()
                grp = next((g for pre, g in _PROP_GROUPS if client.startswith(pre)), None)
                if grp and ver:
                    self.add(ECO, f"{grp}:{client}", ver, "properties", loc)
            elif re.match(r"^(dex/)?classes\d*\.dex$", s):
                dex_files.append(n)
            elif s.startswith("lib/") and s.endswith(".so"):
                so_files.append(n)
            elif s.startswith("assets/") and (s.endswith((".bundle", ".js", ".html")) or s.endswith(".jsbundle")):
                js_files.append(n)
            elif s.lower().endswith(".apk"):
                try:
                    self.scan_zip(SafeZipFile(io.BytesIO(zf.read(n))), f"{label}!/{n}")
                except zipfile.BadZipFile:
                    pass
        packers = sorted({name for n in so_files + [x for x in names if x.startswith("assets/")]
                          for rx, name in PACKERS if rx.search(n)})
        if packers:
            self.notes.append(("packed", label, f"Uygulama koruması / paketleyici: {', '.join(packers)}"))
        self._scan_dex(zf, dex_files, label)
        self._scan_native(zf, so_files, label, is_flutter)
        self._scan_js(zf, js_files, label)

    def _scan_dex(self, zf, dex_files, label):
        classes = obf = 0
        prefixes = set()
        for n in dex_files:
            data = zf.read(n)
            for st in dex_strings(data):
                if st.startswith("L") and st.endswith(";"):
                    classes += 1
                    if re.match(r"^L[a-z]{1,2}/[a-z]{1,2}/", st) or re.match(r"^L[a-z]{1,2};$", st):
                        obf += 1
                    best = max((pre for pre in DEX_PREFIXES if st.startswith(pre)), key=len, default=None)
                    if best:
                        prefixes.add((best, DEX_PREFIXES[best]))
                    continue
                for rx, name_fn in DEX_VERSION_STRINGS:
                    m = rx.match(st)
                    if m:
                        self.add(ECO, name_fn(m.group(1)), m.group(1), "dex-strings", f"{label}!/{n}",
                                 detail=st[:80], confidence="medium")
        if classes and obf / classes > 0.25:
            self.notes.append(("obfuscated", label, f"{obf}/{classes} sınıf adı kısaltılmış (R8/ProGuard)"))
        versioned_groups = {c.name.split(":")[0] for c in self.comps if c.version}
        for pre, mvn in sorted(prefixes):
            if mvn.split(":")[0] not in versioned_groups and mvn not in self.unversioned:
                self.unversioned[mvn] = pre
                self.add(ECO, mvn, None, "dex-strings", label, detail=f"sınıf öneki {pre}")

    def _scan_native(self, zf, so_files, label, is_flutter):
        seen = set()
        pub_pkgs = set()
        for n in so_files:
            data = zf.read(n)
            loc = f"{label}!/{n}"
            for eco, name, ver, snippet in scan_native(data):
                if (name, ver) not in seen:
                    seen.add((name, ver))
                    self.add(eco, name, ver, "binary-strings", loc, detail=snippet,
                             confidence="low" if name == "sqlite" else "medium")
            if is_flutter and n.endswith("libapp.so"):
                pub_pkgs |= {p.decode() for p in re.findall(rb"package:([a-z0-9_]+)/", data)}
        for p in sorted(pub_pkgs - {"flutter", "flutter_test", "dart"}):
            self.add("Pub", p, None, "binary-strings", f"{label}!/libapp.so", detail="Dart paket URI'si")
        if is_flutter:
            self.notes.append(("no-osv-coverage", label,
                               "Flutter: Dart paketlerinin sürümleri derlenmiş uygulamadan okunamaz; pubspec.lock gerekir"))

    def _scan_js(self, zf, js_files, label):
        for n in js_files:
            data = zf.read(n)
            loc = f"{label}!/{n}"
            if data[:4] == b"\xc6\x1f\xbc\x03":
                text = _strings_from_binary(data, 5)
                self.notes.append(("obfuscated", loc, "React Native Hermes bytecode"))
            else:
                text = data.decode("utf-8", "replace")
            for name, ver, snippet in scan_js(text):
                self.add("npm", name, ver, "signature", loc, detail=snippet, confidence="medium")
            m = re.search(r"major:\s*0,\s*minor:\s*(\d+),\s*patch:\s*(\d+)", text)
            if m and n.endswith(".bundle"):
                self.add("npm", "react-native", f"0.{m.group(1)}.{m.group(2)}", "signature", loc,
                         detail="ReactNativeVersion", confidence="medium")
            cm = re.search(r"PLATFORM_VERSION_BUILD_LABEL\s*=\s*['\"](\d+\.\d+\.\d+)", text)
            if cm:
                self.add("npm", "cordova-android", cm.group(1), "signature", loc, confidence="medium")


def scan_apk(path: str, target: str = "", log=None):
    s = ApkScanner(target or Path(path).name, log)
    with SafeZipFile(path) as zf:
        s.scan_zip(zf, Path(path).name)
    if log:
        log(f"  {len(s.comps)} tespit ({sum(1 for c in s.comps if c.version)} sürümlü)")
    return s.comps, s.notes
