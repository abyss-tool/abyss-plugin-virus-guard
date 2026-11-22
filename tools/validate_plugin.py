#!/usr/bin/env python3
"""插件仓 CI 门禁：plugin.json / CHANGELOG / 补丁通道三处一致性校验。

病毒拦截插件新增校验项：
  - category = system（v0.8.0 起病毒拦截为系统工具域的引擎级插件）
  - shizuku 独立授权声明（ownAuth + reason）—— 本插件为独立 APK，
    安装监听与静默处置依赖 Shizuku shell 上下文，需用户单独授权。
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import minisign_py

# N-SEC-001：公钥唯一事实源 = 主仓 ChannelSignatureVerifier.kt TRUSTED_KEYS
#（轮换走双公钥：新增不替换）。
_TRUSTED_PUBKEYS = [
    """
    untrusted comment: Abyss-Tools manifest signing public key (meng4117222)
    RWRx16ORC4gsdxs6DsnctDYagiRptPX1NgFcVpQNYqh/BXGhPAHebh3B
    """,
]

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
REQUIRED = ("id", "name", "repo", "category", "version", "minApp", "summary")
CATEGORIES = {"terminal", "system", "sandbox", "disguise", "media",
              "automation", "desktop", "network", "data", "tools", "dev"}

errors = []


def fail(msg):
    errors.append(msg)


manifest = json.loads(Path("plugin.json").read_text(encoding="utf-8"))
repo_full = Path(".git/config").read_text(encoding="utf-8")
expected_repo = None
for line in repo_full.splitlines():
    if "url = https://github.com/" in line:
        expected_repo = line.split("github.com/")[1].removesuffix(".git").strip()
        break
if expected_repo is None:
    expected_repo = __import__("os").environ.get("GITHUB_REPOSITORY", "")

for field in REQUIRED:
    if not manifest.get(field):
        fail(f"plugin.json 缺少必填字段 {field}")

pid = manifest.get("id", "")
if not re.match(r"^abyss-plugin-[a-z0-9]+(-[a-z0-9]+)*$", pid):
    fail(f"插件 id 形态非法 → {pid!r}")
if expected_repo and manifest.get("repo") != expected_repo:
    fail(f"plugin.json.repo({manifest.get('repo')}) 与仓库({expected_repo})不一致")
if expected_repo and not expected_repo.endswith(pid):
    fail("仓库名末段应等于插件 id")
if manifest.get("category") not in CATEGORIES:
    fail(f"category 非法 → {manifest.get('category')!r}")
for key in ("version", "minApp"):
    if not SEMVER.match(manifest.get(key, "")):
        fail(f"plugin.json.{key} 非法 SemVer → {manifest.get(key)!r}")
if not isinstance(manifest.get("minHost", 1), int) or manifest.get("minHost", 0) < 1:
    fail("plugin.json.minHost 应为正整数")

# ── Shizuku 独立授权声明（本插件必填，且 ownAuth 必须为 true）──────────
shizuku = manifest.get("shizuku")
if not isinstance(shizuku, dict):
    fail("plugin.json.shizuku 声明缺失 —— 安装监听与静默处置依赖 Shizuku shell 上下文，必须向用户明示独立授权")
else:
    if shizuku.get("ownAuth") is not True:
        fail("plugin.json.shizuku.ownAuth 声明即独立授权，必须为 true")
    if not shizuku.get("reason") or "Shizuku" not in shizuku["reason"]:
        fail("plugin.json.shizuku.reason 缺失或未说明 Shizuku 授权原因")

# ── 补丁通道三处一致性 ───────────────────────────────────────────────
channel = json.loads(Path("patches/index.json").read_text(encoding="utf-8"))
if channel.get("schema") != "abyss-plugin-patches-v1":
    fail("patches/index.json.schema 应为 abyss-plugin-patches-v1")
if channel.get("plugin") != pid:
    fail(f"patches/index.json.plugin({channel.get('plugin')}) 与插件 id 不一致")
if not SEMVER.match(channel.get("latest", "")):
    fail(f"patches/index.json.latest 非法 SemVer → {channel.get('latest')!r}")
if channel.get("latest") != manifest.get("version"):
    fail(f"补丁通道 latest({channel.get('latest')}) 与 manifest version({manifest.get('version')}) 不一致")
seen = set()
for p in channel.get("patches", []):
    key = (p.get("from"), p.get("to"))
    if key in seen:
        fail(f"patches/index.json: 重复补丁段 {key}")
    seen.add(key)
    if not SEMVER.match(p.get("from", "")) or not SEMVER.match(p.get("to", "")):
        fail(f"patches/index.json: 补丁段版本非 SemVer → {key}")
    if p.get("to") != manifest.get("version") and p.get("to") != channel.get("latest"):
        if p.get("to") > manifest.get("version"):
            fail(f"patches/index.json: 段终点({p.get('to')})高于 manifest 版本({manifest.get('version')})")

# ── CHANGELOG 条目纪律（一版一条）───────────────────────────────────
changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
if f"## v{manifest.get('version')}" not in changelog:
    fail(f"CHANGELOG.md 缺少当前版本条目 ## v{manifest.get('version')}")

# ── N-SEC-001：补丁通道 detached 签名断言（存在必可验，缺失即拒）────
_sig_path = Path("patches/index.json.minisig")
if not _sig_path.exists():
    fail("patches/index.json.minisig 缺失 —— N-SEC-001 起补丁通道签名强制"
         "（由 patch-release.yml 以 RELEASE_SIGNING_KEY secret 原子产出；"
         "客户端对补丁通道先验签再解析，无签名 = 不信任）")
else:
    _raw = Path("patches/index.json").read_bytes()
    if not any(minisign_py.verify(pk, _sig_path.read_text(encoding="utf-8"), _raw)
               for pk in _TRUSTED_PUBKEYS):
        fail("patches/index.json.minisig 验签失败 —— 通道字节与签名不配对（公钥不匹配或清单被改）")
    else:
        print("[plugin-ci] ✓ 补丁通道 detached 签名验签通过")

if errors:
    print(f"[virusguard-ci] ✗ {len(errors)} 处校验失败：", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(1)
print(f"[virusguard-ci] ✓ 插件清单 / 补丁通道 / changelog 三处一致性校验通过（v{manifest.get('version')}）")
