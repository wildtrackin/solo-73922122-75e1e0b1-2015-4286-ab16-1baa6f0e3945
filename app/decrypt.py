"""AES-256-GCM 日志解密下载：流式上传、认证与明文下载。

设计要点（对应应急响应场景的安全要求）：

* 密钥在服务启动时从配置指定的 32 字节文件读取（环境变量 GCM_KEY_FILE），
  缺失或长度不符直接拒绝启动；密钥不分发、不出现在页面与日志中。
* 上传、认证、下载三个阶段全部按固定大小分块流式处理，内存占用与文件大小无关：
    - 上传：multipart 解析由 Starlette 流式写入滚动临时文件（内存上限 1 MiB），
      再按 1 MiB 块转存到本请求专属的密文暂存文件，同时精确执行 128 MiB 上限；
    - 认证：从暂存文件逐块解密并**随即丢弃明文**，只做 GCM tag 校验；
    - 下载：认证全部通过后，重新打开暂存文件逐块解密并流式返回。
* 完整认证通过之前不返回任何成功状态与明文；篡改、截断、超限一律不输出明文。
* 密文允许暂存磁盘（每请求一个 mkstemp 独立文件，0600）；**明文永不写入
  文件、数据库或日志**——认证阶段的明文块立即丢弃，下载阶段的明文块直接发往客户端。
* 每个请求的临时文件路径唯一，清理只针对本请求的路径（幂等 unlink），
  不扫描、不批量删除目录，并发请求互不影响；上传中断、认证失败、
  下载完成或断连都会清理本请求的暂存文件。
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile

# ---------------------------------------------------------------------------
# 启动配置与常量
# ---------------------------------------------------------------------------

MAX_CIPHERTEXT_BYTES = 128 * 1024 * 1024   # 128 MiB 密文上限
KEY_SIZE = 32                              # AES-256
NONCE_SIZE = 12                            # GCM 标准 nonce
TAG_SIZE = 16                              # GCM 标准 tag
CHUNK_SIZE = 1024 * 1024                   # 1 MiB 流式块：三阶段共用，内存与文件大小无关

# multipart 表单除密文本体外的框架开销宽限（boundary、nonce/tag 字段等），
# 仅用于依据 Content-Length 尽早拒绝明显超限的请求体；精确上限在转存时执行。
_MULTIPART_SLACK = 64 * 1024

_BASE_DIR = Path(__file__).resolve().parent
_DEFAULT_KEY_FILE = _BASE_DIR.parent / "demo" / "gcm-demo-key.bin"

KEY_FILE = os.environ.get("GCM_KEY_FILE", str(_DEFAULT_KEY_FILE))
UPLOAD_DIR = os.environ.get(
    "GCM_UPLOAD_DIR",
    os.path.join(tempfile.gettempdir(), "incident-gcm-uploads"),
)


def load_key(path: str) -> bytes:
    """从启动配置指定的文件读取 32 字节密钥；任何不符都在启动阶段直接失败。"""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise RuntimeError(f"无法读取 GCM 密钥文件 {path!r}：{exc}") from exc
    if len(data) != KEY_SIZE:
        raise RuntimeError(
            f"GCM 密钥文件 {path!r} 必须恰好 {KEY_SIZE} 字节，实际为 {len(data)} 字节")
    return data


# 模块导入（即服务启动）时加载密钥：配置错误在启动阶段暴露，而不是首个请求时。
KEY = load_key(KEY_FILE)


def ensure_upload_dir() -> None:
    """创建密文暂存目录（0700）。Compose 中通常以 tmpfs 挂载，仅驻留内存。"""
    os.makedirs(UPLOAD_DIR, mode=0o700, exist_ok=True)
    try:
        os.chmod(UPLOAD_DIR, 0o700)
    except OSError:
        pass


ensure_upload_dir()


def _new_temp_file() -> tuple[int, Path]:
    """为本请求创建独立的密文暂存文件（mkstemp：唯一名、0600）。"""
    fd, path = tempfile.mkstemp(prefix="ct-", suffix=".bin", dir=UPLOAD_DIR)
    return fd, Path(path)


def _safe_unlink(path: Path) -> None:
    """幂等删除本请求的暂存文件；只针对明确属于本请求的路径。"""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# 输入解析
# ---------------------------------------------------------------------------

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def parse_hex(value, size: int, field: str) -> bytes:
    """解析十六进制字段，必须恰好 size 字节（size*2 个字符）。"""
    text = value.strip() if isinstance(value, str) else ""
    if len(text) != size * 2 or not _HEX_RE.match(text):
        raise ValueError(
            f"字段 {field} 必须是 {size} 字节的十六进制串（{size * 2} 个字符），"
            f"当前为 {len(text)} 个字符")
    return bytes.fromhex(text)


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def download_filename(original) -> str:
    """由上传文件名生成安全的下载文件名（防目录穿越与响应头注入）。"""
    name = _SAFE_NAME_RE.sub("_", os.path.basename(original or "")).strip("._")[:80]
    return f"decrypted-{name or 'log.bin'}"


# ---------------------------------------------------------------------------
# 流式认证与流式解密（同步函数/生成器，由调用方放入线程池执行）
# ---------------------------------------------------------------------------

def verify_ciphertext(path: Path, key: bytes, nonce: bytes, tag: bytes) -> None:
    """逐块解密整份密文并**丢弃明文**，仅校验 GCM tag（AAD 固定为空）。

    认证失败抛出 InvalidTag；全程只有固定大小的密文/明文块经过内存。
    """
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            decryptor.update(chunk)  # 返回的明文块随即丢弃，不落盘、不进日志
    decryptor.finalize()           # tag 校验在此发生，失败抛 InvalidTag


def iter_plaintext(path: Path, key: bytes, nonce: bytes, tag: bytes):
    """认证通过后再次流式解密，逐块产出明文（同步生成器，由 Starlette 放入线程池）。

    生成器结束或被关闭（客户端断连）时，在 finally 中删除本请求的暂存文件。
    """
    try:
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                data = decryptor.update(chunk)
                if data:
                    yield data
        # 该文件已通过完整认证且此后无人改写，正常不会失败；万一失败则中断输出。
        decryptor.finalize()
    finally:
        _safe_unlink(path)


class CleanupStreamingResponse(StreamingResponse):
    """流式响应结束后（含正常完成、客户端断连、异常）确定性地执行清理。"""

    def __init__(self, *args, cleanup=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._cleanup = cleanup

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            if self._cleanup is not None:
                self._cleanup()


# ---------------------------------------------------------------------------
# 演示样例：用启动密钥在启动时生成（固定 nonce，仅用于演示）
# ---------------------------------------------------------------------------

_SAMPLE_NONCE = bytes.fromhex("6f6369676d2d64656d6f3031")  # "ocigm-demo01"，仅演示用途

_SAMPLE_PLAINTEXT = (
    b"2026-11-08T03:12:44Z collector=edge-01 event=connection "
    b"src=10.20.30.40:51022 dst=172.16.0.8:443 proto=tcp action=allow bytes=18234\n"
    b"2026-11-08T03:12:45Z collector=edge-01 event=dns "
    b"src=10.20.30.40:53310 dst=172.16.0.53:53 proto=udp query=update.corp.example\n"
    b"2026-11-08T03:13:02Z collector=edge-01 event=connection "
    b"src=10.20.30.41:49200 dst=172.16.0.40:3306 proto=tcp action=deny rule=db-segment\n"
    b"2026-11-08T03:14:19Z collector=edge-01 event=alert "
    b"msg=\"collector clock skew corrected\" offset_ms=182\n"
    b"2026-11-08T03:15:30Z collector=edge-01 event=connection "
    b"src=192.168.1.22:60115 dst=10.0.0.10:443 proto=tcp action=allow bytes=90311\n"
)


def _build_samples(key: bytes) -> dict:
    """生成正常 / 篡改 / 截断三份样例密文（共用同一 nonce 与 tag）。"""
    sealed = AESGCM(key).encrypt(_SAMPLE_NONCE, _SAMPLE_PLAINTEXT, None)
    ct, tag = sealed[:-TAG_SIZE], sealed[-TAG_SIZE:]
    tampered = bytearray(ct)
    tampered[len(tampered) // 2] ^= 0x01
    return {
        "nonce": _SAMPLE_NONCE,
        "tag": tag,
        "plaintext_size": len(_SAMPLE_PLAINTEXT),
        "good": ct,
        "tampered": bytes(tampered),
        "truncated": ct[: len(ct) // 2],
    }


SAMPLES = _build_samples(KEY)

# ---------------------------------------------------------------------------
# 路由
# ---------------------------------------------------------------------------

router = APIRouter()


def _error(message: str, status: int) -> JSONResponse:
    return JSONResponse({"ok": False, "error": message}, status_code=status)


@router.get("/api/decrypt/samples")
def sample_info():
    """样例密文对应的 nonce/tag（十六进制）与说明。"""
    return {
        "ok": True,
        "nonce": SAMPLES["nonce"].hex(),
        "tag": SAMPLES["tag"].hex(),
        "nonce_bytes": NONCE_SIZE,
        "tag_bytes": TAG_SIZE,
        "plaintext_bytes": SAMPLES["plaintext_size"],
        "note": "三份样例共用同一 nonce/tag；篡改与截断样例必须认证失败且不输出明文。",
    }


@router.get("/api/decrypt/samples/{kind}")
def sample_download(kind: str):
    """下载样例密文：good（正常）/ tampered（篡改）/ truncated（截断）。"""
    if kind not in ("good", "tampered", "truncated"):
        return _error("未知样例类型（可选：good / tampered / truncated）", 404)
    return Response(
        content=SAMPLES[kind],
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="sample-{kind}.bin"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/api/decrypt")
async def decrypt_logs(request: Request):
    """上传密文 + nonce + tag，认证通过后流式返回明文附件。

    任何阶段失败（超限、格式错误、认证失败）都不输出明文。
    """
    # 0) 依据 Content-Length 尽早拒绝明显超限的请求体（精确上限在第 2 步执行）
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            declared_len = int(declared)
        except ValueError:
            declared_len = -1
        if declared_len < 0:
            return _error("非法的 Content-Length 请求头", 400)
        if declared_len > MAX_CIPHERTEXT_BYTES + _MULTIPART_SLACK:
            return _error(
                f"请求体超过上限：密文最大 {MAX_CIPHERTEXT_BYTES} 字节（128 MiB）", 413)

    # 1) 流式解析 multipart 表单（Starlette 将文件部分写入滚动临时文件，
    #    内存占用有界，不随文件大小增长）
    try:
        form = await request.form()
    except Exception:
        return _error(
            "表单解析失败：需要 multipart/form-data，字段为 file / nonce / tag", 400)

    upload = form.get("file")
    if not isinstance(upload, UploadFile):
        return _error("缺少文件字段 file（multipart 文件部分）", 400)

    try:
        # nonce/tag 先校验，避免无谓的磁盘写入
        try:
            nonce = parse_hex(form.get("nonce"), NONCE_SIZE, "nonce")
            tag = parse_hex(form.get("tag"), TAG_SIZE, "tag")
        except ValueError as exc:
            return _error(str(exc), 400)

        # 2) 转存到本请求专属的暂存文件，逐块计数执行精确的 128 MiB 上限
        fd, tmp_path = _new_temp_file()
        handed_off = False
        try:
            size = 0
            with os.fdopen(fd, "wb") as out:
                while True:
                    chunk = await upload.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_CIPHERTEXT_BYTES:
                        return _error(
                            f"密文超过大小上限（{MAX_CIPHERTEXT_BYTES} 字节，128 MiB）", 413)
                    await run_in_threadpool(out.write, chunk)

            # 3) 流式认证整份密文（明文即弃）；失败则不输出任何明文
            try:
                await run_in_threadpool(verify_ciphertext, tmp_path, KEY, nonce, tag)
            except InvalidTag:
                return _error(
                    "密文认证失败：数据被篡改或截断，或密钥 / nonce / tag 不匹配", 400)

            # 4) 认证全部通过：流式返回明文附件；暂存文件随响应结束清理
            response = CleanupStreamingResponse(
                iter_plaintext(tmp_path, KEY, nonce, tag),
                media_type="application/octet-stream",
                headers={
                    "Content-Disposition":
                        f'attachment; filename="{download_filename(upload.filename)}"',
                    "Content-Length": str(size),
                    "Cache-Control": "no-store",
                    "X-Content-Type-Options": "nosniff",
                },
                cleanup=lambda: _safe_unlink(tmp_path),
            )
            handed_off = True
            return response
        finally:
            if not handed_off:
                _safe_unlink(tmp_path)
    finally:
        await upload.close()
