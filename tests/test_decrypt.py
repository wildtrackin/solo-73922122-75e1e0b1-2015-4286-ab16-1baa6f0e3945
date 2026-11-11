"""日志解密下载（AES-256-GCM）测试：

1. 正常往返：多种尺寸（含空文件、跨块大小）加密后上传，认证通过并逐字节返回明文；
2. 篡改 / 截断 / 错误 tag / 非法 hex：一律拒绝且不输出明文；
3. 大小上限：精确边界（超限拒绝、恰好等于上限放行）、Content-Length 预检；
4. 临时文件：成功、认证失败、超限、参数错误后，本请求暂存文件均被清理；
5. 断连清理：响应流中途断开（ASGI 层模拟）后暂存文件被删除；
6. 样例接口：正常样例可解密，篡改/截断样例认证失败；
7. 并发：多请求独立处理，互不干扰，结束后无残留文件；
8. 启动配置：密钥文件缺失或长度不符时拒绝加载。

运行：python3 tests/test_decrypt.py
"""

import asyncio
import os
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

import app.decrypt as decrypt
from app.main import app

KEY = decrypt.KEY
NONCE = bytes.fromhex("0102030405060708090a0b0c")

# 隔离的暂存目录：测试期间接管模块级配置，结束恢复原值
_ORIG_UPLOAD_DIR = decrypt.UPLOAD_DIR
_TMP = tempfile.mkdtemp(prefix="gcm-test-")
decrypt.UPLOAD_DIR = _TMP
decrypt.ensure_upload_dir()


def seal(plaintext: bytes, key: bytes = KEY, nonce: bytes = NONCE):
    """返回 (密文, tag)。"""
    sealed = AESGCM(key).encrypt(nonce, plaintext, None)
    return sealed[:-16], sealed[-16:]


def post(client, ct: bytes, nonce_hex: str, tag_hex: str, filename="capture.bin"):
    return client.post(
        "/api/decrypt",
        files={"file": (filename, ct, "application/octet-stream")},
        data={"nonce": nonce_hex, "tag": tag_hex},
    )


def leftover_files():
    return list(Path(_TMP).iterdir())


def make_plaintext(size: int) -> bytes:
    block = b"incident-log-line SECRET \x00\xff\n"
    return (block * (size // len(block) + 1))[:size]


def test_roundtrip():
    with TestClient(app) as client:
        for size in (0, 1, 100, 1024 * 1024 + 7, 5 * 1024 * 1024 + 123):
            plaintext = make_plaintext(size)
            assert len(plaintext) == size
            ct, tag = seal(plaintext)
            assert len(ct) == size  # GCM 密文与明文等长
            res = post(client, ct, NONCE.hex(), tag.hex())
            assert res.status_code == 200, (size, res.status_code, res.text[:200])
            assert res.content == plaintext, f"size={size} 明文不一致"
            assert 'attachment; filename="decrypted-capture.bin"' in \
                res.headers["content-disposition"]
            assert res.headers["content-length"] == str(size)
            assert res.headers["x-content-type-options"] == "nosniff"
    assert not leftover_files(), "成功后暂存文件未清理"
    print("[1] 正常往返通过：0 / 1 / 100 / 1MiB+7 / 5MiB+123 字节，"
          "明文逐字节一致，附件头与 Content-Length 正确")


def test_tamper_truncate_rejected():
    marker = b"TOP-SECRET-PLAINTEXT-MARKER"
    plaintext = marker * 5000
    ct, tag = seal(plaintext)
    with TestClient(app) as client:
        # 篡改：翻转中间一个字节
        bad = bytearray(ct)
        bad[len(bad) // 2] ^= 0x01
        res = post(client, bytes(bad), NONCE.hex(), tag.hex())
        assert res.status_code == 400, res.status_code
        assert "认证失败" in res.json()["error"]
        assert marker not in res.content, "篡改输入泄露了明文"

        # 截断：只上传前一半
        res = post(client, ct[: len(ct) // 2], NONCE.hex(), tag.hex())
        assert res.status_code == 400
        assert "认证失败" in res.json()["error"]
        assert marker not in res.content

        # 错误 tag（合法 hex 但内容不符）
        wrong_tag = bytes(b ^ 0xFF for b in tag)
        res = post(client, ct, NONCE.hex(), wrong_tag.hex())
        assert res.status_code == 400
        assert marker not in res.content

        # 错误 nonce（合法 hex 但内容不符）
        wrong_nonce = bytes(b ^ 0x01 for b in NONCE)
        res = post(client, ct, wrong_nonce.hex(), tag.hex())
        assert res.status_code == 400
        assert marker not in res.content

        # 错误密钥加密的密文
        other_key = os.urandom(32)
        ct2, tag2 = seal(plaintext, key=other_key)
        res = post(client, ct2, NONCE.hex(), tag2.hex())
        assert res.status_code == 400
        assert marker not in res.content
    assert not leftover_files(), "认证失败后暂存文件未清理"
    print("[2] 篡改 / 截断 / 错误 tag / 错误 nonce / 错误密钥："
          "均 400 拒绝且响应中无任何明文")


def test_bad_hex_rejected():
    ct, tag = seal(b"x" * 64)
    with TestClient(app) as client:
        for nonce_hex, tag_hex, needle in (
            ("0011", tag.hex(), "nonce"),                # nonce 太短
            (NONCE.hex() + "00", tag.hex(), "nonce"),    # nonce 太长
            ("zz" * 12, tag.hex(), "nonce"),             # 非 hex
            ("", tag.hex(), "nonce"),                    # 空
            (NONCE.hex(), "aabb", "tag"),                # tag 太短
            (NONCE.hex(), tag.hex() + "00", "tag"),      # tag 太长
            (NONCE.hex(), "gg" * 16, "tag"),             # 非 hex
        ):
            res = post(client, ct, nonce_hex, tag_hex)
            assert res.status_code == 400, (nonce_hex, tag_hex, res.status_code)
            assert needle in res.json()["error"]
        # 缺少文件字段 / 缺少 nonce、tag 字段
        res = client.post("/api/decrypt",
                          data={"nonce": NONCE.hex(), "tag": tag.hex()})
        assert res.status_code == 400 and "file" in res.json()["error"]
        res = client.post("/api/decrypt",
                          files={"file": ("a.bin", ct)},
                          data={"nonce": NONCE.hex()})
        assert res.status_code == 400 and "tag" in res.json()["error"]
    assert not leftover_files(), "参数错误后暂存文件未清理"
    print("[3] 非法 hex / 缺字段：均 400 拒绝并指明字段，无暂存文件残留")


def test_size_limit():
    saved = decrypt.MAX_CIPHERTEXT_BYTES
    decrypt.MAX_CIPHERTEXT_BYTES = 4096
    try:
        with TestClient(app) as client:
            # 恰好等于上限：放行
            ct, tag = seal(b"y" * 4096)
            res = post(client, ct, NONCE.hex(), tag.hex())
            assert res.status_code == 200 and res.content == b"y" * 4096

            # 超 1 字节：精确计数拒绝（413）
            ct, tag = seal(b"y" * 4097)
            res = post(client, ct, NONCE.hex(), tag.hex())
            assert res.status_code == 413 and "密文超过" in res.json()["error"]
            assert b"y" * 100 not in res.content

            # 远超上限：Content-Length 预检直接拒绝（413）
            big = b"z" * (4096 + 64 * 1024 + 1)
            res = post(client, big, NONCE.hex(), tag.hex())
            assert res.status_code == 413 and "请求体超过" in res.json()["error"]
    finally:
        decrypt.MAX_CIPHERTEXT_BYTES = saved
    assert not leftover_files(), "超限拒绝后暂存文件未清理"
    print("[4] 大小上限：恰好等于上限放行，超 1 字节与远超均 413 且不输出明文")


def test_disconnect_cleanup():
    """响应流中途断开（模拟客户端断连）后，本请求暂存文件被删除。"""
    plaintext = b"stream-me " * 20000
    ct, tag = seal(plaintext)
    fd, path = decrypt._new_temp_file()
    with os.fdopen(fd, "wb") as f:
        f.write(ct)

    resp = decrypt.CleanupStreamingResponse(
        decrypt.iter_plaintext(path, KEY, NONCE, tag),
        media_type="application/octet-stream",
        cleanup=lambda: decrypt._safe_unlink(path),
    )

    async def run():
        sent = {"n": 0}

        async def receive():
            return {"type": "http.request"}

        async def send(message):
            sent["n"] += 1
            if sent["n"] >= 2:  # 响应头之后的第一块正文就"断开"
                raise OSError("client disconnected")

        scope = {"type": "http", "asgi": {"spec_version": "2.4"}}
        try:
            await resp(scope, receive, send)
        except Exception:
            pass

    asyncio.run(run())
    assert not path.exists(), "断连后暂存文件未被清理"
    assert not leftover_files()
    print("[5] 断连清理：响应流中途断开，暂存文件即被删除")


def test_iter_plaintext_generator():
    """生成器：完整消费与提前关闭都会删除暂存文件，且输出与明文一致。"""
    plaintext = b"generator-check " * 1000
    ct, tag = seal(plaintext)

    fd, path = decrypt._new_temp_file()
    with os.fdopen(fd, "wb") as f:
        f.write(ct)
    out = b"".join(decrypt.iter_plaintext(path, KEY, NONCE, tag))
    assert out == plaintext
    assert not path.exists(), "完整消费后暂存文件未删除"

    fd, path = decrypt._new_temp_file()
    with os.fdopen(fd, "wb") as f:
        f.write(ct)
    it = decrypt.iter_plaintext(path, KEY, NONCE, tag)
    next(it)          # 只消费一块就关闭（模拟下载中止）
    it.close()
    assert not path.exists(), "提前关闭后暂存文件未删除"
    print("[6] 解密生成器：输出正确，完整消费 / 提前关闭均删除暂存文件")


def test_samples():
    with TestClient(app) as client:
        info = client.get("/api/decrypt/samples").json()
        assert info["ok"] and len(info["nonce"]) == 24 and len(info["tag"]) == 32

        good = client.get("/api/decrypt/samples/good").content
        tampered = client.get("/api/decrypt/samples/tampered").content
        truncated = client.get("/api/decrypt/samples/truncated").content
        assert len(good) == info["plaintext_bytes"]
        assert len(tampered) == len(good) and tampered != good
        assert 0 < len(truncated) < len(good)

        # 正常样例：认证通过，解密出演示日志
        res = post(client, good, info["nonce"], info["tag"])
        assert res.status_code == 200
        assert b"collector=edge-01" in res.content
        assert len(res.content) == info["plaintext_bytes"]

        # 篡改 / 截断样例：认证失败，不输出明文
        for name, data in (("tampered", tampered), ("truncated", truncated)):
            res = post(client, data, info["nonce"], info["tag"])
            assert res.status_code == 400, name
            assert b"collector=edge-01" not in res.content

        # 未知样例类型
        assert client.get("/api/decrypt/samples/nope").status_code == 404
    assert not leftover_files()
    print("[7] 样例接口：正常样例可解密，篡改 / 截断样例认证失败且无明文")


def test_concurrent_independent():
    """8 个并发请求各自独立加解密，结果互不串扰，结束后无残留文件。"""
    results = {}
    errors = []

    def worker(i):
        try:
            plaintext = (f"thread-{i} ".encode() * 30000)[:200_000 + i * 137]
            ct, tag = seal(plaintext, nonce=bytes([i]) * 12)
            with TestClient(app) as c:  # 每线程独立客户端
                res = post(c, ct, (bytes([i]) * 12).hex(), tag.hex(),
                           filename=f"case-{i}.bin")
            results[i] = (res.status_code, res.content == plaintext)
        except Exception as exc:  # noqa: BLE001
            errors.append((i, exc))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"并发请求出错: {errors}"
    assert len(results) == 8 and all(v == (200, True) for v in results.values()), results
    assert not leftover_files(), "并发结束后有暂存文件残留"
    print("[8] 并发：8 个请求独立处理，明文各自正确，无暂存文件残留")


def test_key_loading():
    good = decrypt.load_key(decrypt.KEY_FILE)
    assert good == KEY and len(good) == 32

    with tempfile.TemporaryDirectory() as d:
        short = Path(d) / "short.bin"
        short.write_bytes(b"\x00" * 31)
        try:
            decrypt.load_key(str(short))
            raise AssertionError("31 字节密钥应被拒绝")
        except RuntimeError as e:
            assert "32" in str(e)
        try:
            decrypt.load_key(str(Path(d) / "missing.bin"))
            raise AssertionError("缺失密钥文件应被拒绝")
        except RuntimeError:
            pass
    print("[9] 启动配置：密钥文件缺失或长度不符均拒绝加载")


def test_pages():
    with TestClient(app) as client:
        home = client.get("/")
        assert home.status_code == 200 and "/decrypt" in home.text
        page = client.get("/decrypt")
        assert page.status_code == 200
        for needle in ("nonce", "tag", "/api/decrypt", "sample-good.bin"):
            assert needle in page.text, needle
    print("[10] 页面：首页已接入解密入口，/decrypt 页面可访问")


if __name__ == "__main__":
    try:
        test_roundtrip()
        test_tamper_truncate_rejected()
        test_bad_hex_rejected()
        test_size_limit()
        test_disconnect_cleanup()
        test_iter_plaintext_generator()
        test_samples()
        test_concurrent_independent()
        test_key_loading()
        test_pages()
    finally:
        decrypt.UPLOAD_DIR = _ORIG_UPLOAD_DIR
    print("全部测试通过。")
