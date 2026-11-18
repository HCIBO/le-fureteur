import unittest

from scakit.messages import translate


class TranslateTest(unittest.TestCase):
    def test_exact_and_template(self):
        self.assertEqual(translate("Bulunamadı", "en"), "Not found")
        self.assertEqual(translate("Parola en az 10 karakter olmalı", "en"), "The password must be at least 10 characters long")
        self.assertEqual(translate("Proje bulunamadı", "de"), "Projekt nicht gefunden")
        self.assertEqual(translate("Bağlantı kurulamadı: Sunucu adı çözümlenemedi (DNS)", "en"),
                         "Could not connect: Server name could not be resolved (DNS)")

    def test_passthrough(self):
        self.assertEqual(translate("Bulunamadı", "tr"), "Bulunamadı")
        self.assertEqual(translate("plain english text", "fr"), "plain english text")
        self.assertEqual(translate("", "en"), "")

    def test_server_texts_are_translated(self):
        import pathlib
        import re
        import sys
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "frontend" / "i18n"))
        import build
        shapes = {build._shape(k) for k in build.T}
        missing = [(t, f, n) for t, f, n in build.backend_texts() if build._shape(t) not in shapes]
        self.assertEqual(missing, [])
        bad = [k for k, v in build.T.items() for x in v
               if x and set(re.findall(r"\{\w+\}", k)) != set(re.findall(r"\{\w+\}", x))]
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
