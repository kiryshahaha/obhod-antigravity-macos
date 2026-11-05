#!/usr/bin/env python3
"""
Unit tests for Antigravity Mac Unlocker.
"""

import unittest
import tempfile
import base64
from pathlib import Path

from ag_unlocker import (
    UpstreamProxy,
    patch_binary_file,
    unpatch_binary_file,
    inspect_binary,
    patch_ide_main_js,
    patch_extension_js,
    patch_desktop_main_js,
    PATCH_INELIGIBLE_OLD,
    PATCH_INELIGIBLE_NEW,
    PATCH_TIERS_OLD,
    PATCH_TIERS_NEW,
    PATCH_PROXY_OLD,
    PATCH_PROXY_NEW,
)


class TestMacUnlocker(unittest.TestCase):

    def test_parse_user_requested_proxy(self):
        url = "http://username:secretpass@proxy.example.com:8080"
        up = UpstreamProxy.parse(url)
        self.assertEqual(up.host, "proxy.example.com")
        self.assertEqual(up.port, 8080)
        self.assertEqual(up.user, "username")
        self.assertEqual(up.password, "secretpass")
        self.assertEqual(up.display(), "http://username:***@proxy.example.com:8080")

        # Проверяем Basic Auth
        expected_b64 = base64.b64encode(b"username:secretpass").decode("ascii")
        self.assertEqual(up.auth_header, f"Basic {expected_b64}")

    def test_parse_proxy_variations(self):
        # Без схемы http://
        up1 = UpstreamProxy.parse("user:pass@192.168.1.100:3128")
        self.assertEqual(up1.host, "192.168.1.100")
        self.assertEqual(up1.port, 3128)
        self.assertEqual(up1.user, "user")
        self.assertEqual(up1.password, "pass")

        # Без авторизации
        up2 = UpstreamProxy.parse("http://192.168.1.100:3128")
        self.assertEqual(up2.host, "192.168.1.100")
        self.assertEqual(up2.port, 3128)
        self.assertIsNone(up2.user)
        self.assertIsNone(up2.password)
        self.assertEqual(up2.auth_header, "")
        self.assertEqual(up2.display(), "http://192.168.1.100:3128")

        # Пароль с символом '@'
        up3 = UpstreamProxy.parse("http://john:secret@123@proxy.org:8080")
        self.assertEqual(up3.host, "proxy.org")
        self.assertEqual(up3.port, 8080)
        self.assertEqual(up3.user, "john")
        self.assertEqual(up3.password, "secret@123")

    def test_parse_invalid_proxy(self):
        with self.assertRaises(ValueError):
            UpstreamProxy.parse("")
        with self.assertRaises(ValueError):
            UpstreamProxy.parse("socks5://127.0.0.1:1080")
        with self.assertRaises(ValueError):
            UpstreamProxy.parse("192.168.1.100")  # без порта
        with self.assertRaises(ValueError):
            UpstreamProxy.parse("user@192.168.1.100:3128")  # логин без пароля

    def test_binary_patching_and_unpatching(self):
        # Создаем фиктивный бинарник с характерными последовательностями
        dummy_content = (
            b"HEADER_DATA\x00\x01\x02"
            + PATCH_INELIGIBLE_OLD
            + b"\x00MIDDLE\x00"
            + PATCH_TIERS_OLD
            + b"\x00TAIL\x00"
            + PATCH_PROXY_OLD
            + b"\x00END"
        )
        orig_len = len(dummy_content)

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = Path(tmp.name)
            tmp.write(dummy_content)

        try:
            # 1. Проверяем до патча
            info_before = inspect_binary(tmp_path)
            self.assertFalse(info_before["patched_eligibility"])
            self.assertTrue(info_before["can_patch"])

            # 2. Патчим
            ok, msg = patch_binary_file(tmp_path)
            self.assertTrue(ok)

            patched_data = tmp_path.read_bytes()
            # Длина бинарника НЕ должна меняться
            self.assertEqual(len(patched_data), orig_len)

            # Проверяем наличие новых сигнатур
            self.assertIn(PATCH_INELIGIBLE_NEW, patched_data)
            self.assertIn(PATCH_TIERS_NEW, patched_data)
            self.assertIn(PATCH_PROXY_NEW, patched_data)

            # Проверяем отсутствие старых сигнатур
            self.assertNotIn(PATCH_INELIGIBLE_OLD, patched_data)
            self.assertNotIn(PATCH_TIERS_OLD, patched_data)
            self.assertNotIn(PATCH_PROXY_OLD, patched_data)

            info_after = inspect_binary(tmp_path)
            self.assertTrue(info_after["patched_eligibility"])
            self.assertTrue(info_after["patched_proxy_var"])

            # 3. Откатываем (unpatch)
            ok_unpatch, _ = unpatch_binary_file(tmp_path)
            self.assertTrue(ok_unpatch)

            reverted_data = tmp_path.read_bytes()
            self.assertEqual(reverted_data, dummy_content)
        finally:
            tmp_path.unlink(missing_ok=True)
            tmp_path.with_name(tmp_path.name + ".ag_backup").unlink(missing_ok=True)

    def test_patch_ide_main_js(self):
        sample_js = (
            'console.log("start");\n'
            'async signInHandler(token){'
            'if(this.actor.send({type:token.isGcpTos?"GCP_SIGN_IN":"SIGN_IN"}),this.client.resetIsTierGCPTos(),this.client.isGoogleInternal){'
            'try{await this.client.loadCodeAssist(token);'
            'const{settings:setVar,userTier:tierVar}=await this.refreshUserStatus(token),infoVar=formatFunc(token);'
            'this.updater.pushUpdate(infoVar),this.actor.send({type:"AUTH_SUCCESS",tokenInfo:token}),this.emitter.fire({settings:setVar,userTier:tierVar})'
            '}catch(err){console.error(err);return;}}\n'
            'console.log("end");'
        )

        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
            tmp_path = Path(f.name)
            f.write(sample_js)

        try:
            ok, msg = patch_ide_main_js(tmp_path)
            self.assertTrue(ok, f"Patch failed: {msg}")

            patched_content = tmp_path.read_text(encoding="utf-8")
            self.assertIn("/*[AG_IDE_PATCHED]*/", patched_content)
            self.assertIn('"pro"', patched_content)
            self.assertIn('onboardUser("standard-tier"', patched_content)

            # Проверяем бэкап
            bak_path = tmp_path.with_name(tmp_path.name + ".ag_backup")
            self.assertTrue(bak_path.is_file())
            self.assertEqual(bak_path.read_text(encoding="utf-8"), sample_js)

            # Повторный вызов должен быть идемпотентным
            ok2, msg2 = patch_ide_main_js(tmp_path)
            self.assertTrue(ok2)
            self.assertIn("Уже", msg2)
        finally:
            tmp_path.unlink(missing_ok=True)
            tmp_path.with_name(tmp_path.name + ".ag_backup").unlink(missing_ok=True)

    def test_patch_extension_js(self):
        sample_ext = (
            'const t=await api.UserStatus.getUserStatus();if(!t)return[];'
            'const n=(0,helper.format)(t,ctx),{email:userMail,name:userName}=n;'
            'return""===userMail?[]:showUser();'
        )

        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
            tmp_path = Path(f.name)
            f.write(sample_ext)

        try:
            ok, msg = patch_extension_js(tmp_path)
            self.assertTrue(ok, f"Patch failed: {msg}")

            patched = tmp_path.read_text(encoding="utf-8")
            self.assertIn("/*[AG_EXT_PATCHED]*/", patched)
            self.assertIn('userMail="antigravity-user"', patched)
            self.assertIn('userName="User"', patched)

            # Повторный вызов
            ok2, _ = patch_extension_js(tmp_path)
            self.assertTrue(ok2)
        finally:
            tmp_path.unlink(missing_ok=True)
            tmp_path.with_name(tmp_path.name + ".ag_backup").unlink(missing_ok=True)

    def test_patch_desktop_main_js(self):
        sample_desktop = (
            'function test() {'
            '_handleAuthErrorResponse(err){var det=err?.failureDetails;'
            'if(other?.failureDetails?.case==="ineligible"?this._authActor.send({type:"SET_INELIGIBLE"}:false){}'
            '}'
        )

        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
            tmp_path = Path(f.name)
            f.write(sample_desktop)

        try:
            ok, msg = patch_desktop_main_js(tmp_path)
            self.assertTrue(ok, f"Patch desktop failed: {msg}")

            patched = tmp_path.read_text(encoding="utf-8")
            self.assertIn('case==="ineligible"', patched)
            self.assertIn('AUTH_SUCCESS', patched)
            self.assertIn('NEVER_MATCH', patched)

            # Повторный вызов
            ok2, _ = patch_desktop_main_js(tmp_path)
            self.assertTrue(ok2)
        finally:
            tmp_path.unlink(missing_ok=True)
            tmp_path.with_name(tmp_path.name + ".ag_backup").unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
