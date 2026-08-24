import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


TESTS_DIR = Path(__file__).resolve().parent
APP_DIR = TESTS_DIR.parent / "securescope"
TEMP_DIR = tempfile.TemporaryDirectory(dir=TESTS_DIR)

os.environ["APP_ENV"] = "testing"
os.environ["USE_SQLITE"] = "1"
os.environ["SQLITE_DATABASE_PATH"] = str(Path(TEMP_DIR.name) / "security-test.db")
os.environ["JWT_SECRET_KEY"] = "test-only-secret-with-at-least-thirty-two-characters"
os.environ["RATELIMIT_STORAGE_URI"] = "memory://"
os.environ["RATELIMIT_LOGIN"] = "3 per minute"
os.environ["RATELIMIT_REGISTER"] = "20 per minute"

sys.path.insert(0, str(APP_DIR))
import app as securescope_app  # noqa: E402


class SecurityControlsTest(unittest.TestCase):
    def setUp(self):
        securescope_app.app.config.update(TESTING=True)
        securescope_app.limiter.reset()
        self.client = securescope_app.app.test_client()
        conn = securescope_app.get_db_connection()
        conn.execute("DELETE FROM usuarios")
        conn.commit()
        conn.close()

    @classmethod
    def tearDownClass(cls):
        if securescope_app.db._sqlite_conn is not None:
            securescope_app.db._sqlite_conn._conn.close()
            securescope_app.db._sqlite_conn = None
        TEMP_DIR.cleanup()

    def _register(self, role="admin"):
        return self.client.post(
            "/auth/register",
            json={
                "nome": "Analista Teste",
                "email": "analista@example.com",
                "senha": "SenhaSegura123",
                "role": role,
            },
        )

    def _login(self):
        return self.client.post(
            "/auth/login",
            json={"email": "analista@example.com", "senha": "SenhaSegura123"},
        )

    def test_public_registration_cannot_choose_privileged_role(self):
        self.assertEqual(self._register(role="admin").status_code, 201)
        login = self._login()
        self.assertEqual(login.status_code, 200)

        profile = self.client.get("/auth/me")
        self.assertEqual(profile.status_code, 200)
        self.assertEqual(profile.get_json()["role"], "analista")

    def test_weak_password_is_rejected(self):
        response = self.client.post(
            "/auth/register",
            json={"nome": "Teste", "email": "teste@example.com", "senha": "123456"},
        )
        self.assertEqual(response.status_code, 400)

    def test_jwt_uses_httponly_cookie_and_csrf(self):
        self._register()
        login = self._login()
        cookies = login.headers.getlist("Set-Cookie")

        access_cookie = next(value for value in cookies if value.startswith("access_token_cookie="))
        self.assertIn("HttpOnly", access_cookie)
        self.assertTrue(any(value.startswith("csrf_access_token=") for value in cookies))

        without_csrf = self.client.post("/auth/logout")
        self.assertEqual(without_csrf.status_code, 401)

        csrf_cookie = self.client.get_cookie("csrf_access_token")
        with_csrf = self.client.post(
            "/auth/logout",
            headers={"X-CSRF-TOKEN": csrf_cookie.value},
        )
        self.assertEqual(with_csrf.status_code, 200)

    def test_login_is_rate_limited_by_ip(self):
        request_data = {"email": "nao-existe@example.com", "senha": "SenhaSegura123"}
        remote = {"REMOTE_ADDR": "198.51.100.20"}

        for _ in range(3):
            response = self.client.post(
                "/auth/login", json=request_data, environ_overrides=remote
            )
            self.assertEqual(response.status_code, 401)

        blocked = self.client.post(
            "/auth/login", json=request_data, environ_overrides=remote
        )
        self.assertEqual(blocked.status_code, 429)

    def test_security_headers_are_present(self):
        response = self.client.get("/home")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        response.close()

    def test_production_rejects_missing_jwt_secret(self):
        env = os.environ.copy()
        env.update({
            "APP_ENV": "production",
            "JWT_SECRET_KEY": "",
            "ALLOWED_ORIGINS": "https://example.com",
            "RATELIMIT_STORAGE_URI": "redis://localhost:6379/0",
        })
        result = subprocess.run(
            [sys.executable, "-c", "import app"],
            cwd=APP_DIR,
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("JWT_SECRET_KEY", result.stderr)

    def test_production_rejects_local_rate_limit_storage(self):
        env = os.environ.copy()
        env.update({
            "APP_ENV": "production",
            "JWT_SECRET_KEY": "production-test-secret-with-more-than-thirty-two-characters",
            "ALLOWED_ORIGINS": "https://example.com",
            "RATELIMIT_STORAGE_URI": "memory://",
        })
        result = subprocess.run(
            [sys.executable, "-c", "import app"],
            cwd=APP_DIR,
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RATELIMIT_STORAGE_URI", result.stderr)


if __name__ == "__main__":
    unittest.main()
