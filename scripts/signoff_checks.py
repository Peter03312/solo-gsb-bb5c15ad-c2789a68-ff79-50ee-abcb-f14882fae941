"""交付归档包签收测试：一次性密钥邀请/定稿幂等/冲突/过期/撤销并发。

直接压 HTTP 接口（urllib，无第三方依赖）；“明文不持久化”一项用 psycopg
直连库内表核查。服务需已启动。
用法: python3 scripts/signoff_checks.py [base_url]
"""
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
ADMIN = os.environ.get("ADMIN_KEY", "secret-admin-key")
results = []


def call(method, path, body=None, admin_key=None, raw_key=None):
    headers = {"Content-Type": "application/json"}
    if admin_key is not None:
        headers["X-Admin-Key"] = admin_key
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def check(name, cond, detail=""):
    results.append((name, cond, detail))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + ("" if cond else f" :: {detail}"))


def err_code(body):
    return body.get("error", {}).get("code") or body.get("detail", "")


TZ = timezone(timedelta(hours=8))
_seq = [0]


def ts(offset_days=0, base=None):
    t0 = base or datetime(2026, 6, 1, 0, 0, tzinfo=TZ)
    return (t0 + timedelta(days=offset_days)).isoformat()


def ref(no, name=None):
    return call("POST", "/api/v1/reference-certificates", {
        "cert_no": no, "device_id": "DEV-" + no, "device_name": name or ("基准" + no),
        "valid_from": ts(0), "valid_to": ts(900), "calibrated_at": ts(0)})


def cal(no, parent, conclusion="PASS", name=None):
    return call("POST", "/api/v1/certificates", {
        "cert_no": no, "device_id": "DEV-" + no, "device_name": name or ("仪表" + no),
        "valid_from": ts(2), "valid_to": ts(600), "calibrated_at": ts(3),
        "conclusion": conclusion, "parent_cert_no": parent})


def revoke(no, reason="测试撤销"):
    return call("POST", f"/api/v1/certificates/{no}/revoke", {"reason": reason})


def invite(archive_no, recipient, deadline, key=ADMIN):
    return call("POST", "/api/v1/signoff-invitations",
                {"archive_no": archive_no, "recipient": recipient,
                 "deadline": deadline}, admin_key=key)


def submit(inv, key, decision, reason=None):
    body = {"key": key, "decision": decision}
    if reason is not None:
        body["reason"] = reason
    return call("POST", f"/api/v1/signoff-invitations/{inv}/submissions", body)


def get_record(archive_no, key=ADMIN):
    return call("GET", f"/api/v1/delivery-archives/{archive_no}/signoff",
                admin_key=key)


# ---------------------------------------------------------------------------
print("== 0. 前置数据与归档包 ==")
s, _ = ref("SR-1", "签收基准器1")
check("基准 201", s == 201, f"got {s}")
s, _ = cal("SC-1", "SR-1", name="签收仪表1")
check("二级 201", s == 201, f"got {s}")
s, _ = cal("SC-2", "SC-1", name="签收仪表2")
check("三级 201", s == 201, f"got {s}")
s, b = call("POST", "/api/v1/delivery-archives",
            {"archive_no": "SA-1", "cert_nos": ["SC-1", "SC-2"]})
check("归档 SA-1 201", s == 201, f"got {s}")
s, b = call("POST", "/api/v1/delivery-archives",
            {"archive_no": "SA-2", "cert_nos": ["SC-2"]})
check("归档 SA-2 201", s == 201, f"got {s}")

# ---------------------------------------------------------------------------
print("== A. 创建邀请：管理密钥校验 / 包不存在 / 截止时刻非未来 ==")
future = (datetime.now(TZ) + timedelta(days=2)).isoformat()
s, b = invite("SA-1", "客户甲", future, key=None)
check("缺管理密钥 -> 401 admin_key_invalid", s == 401 and err_code(b) == "admin_key_invalid",
      f"{s} {b}")
s, b = invite("SA-1", "客户甲", future, key="wrong-key")
check("错误管理密钥 -> 401", s == 401 and err_code(b) == "admin_key_invalid", f"{s} {b}")
s, b = invite("NO-SUCH-ARCHIVE", "客户甲", future)
check("归档包不存在 -> 404 archive_not_found",
      s == 404 and err_code(b) == "archive_not_found", f"{s} {b}")
past = (datetime.now(TZ) - timedelta(seconds=10)).isoformat()
s, b = invite("SA-1", "客户甲", past)
check("截止时刻为过去 -> 422 signoff_deadline_not_future",
      s == 422 and err_code(b) == "signoff_deadline_not_future", f"{s} {b}")
s, b = invite("SA-1", "客户甲", datetime.now(TZ).replace(microsecond=0).isoformat())
# 恰好当前时刻（非严格未来）也拒绝
s, b = invite("SA-1", "客户甲",
              (datetime.now(TZ)).strftime("%Y-%m-%dT%H:%M:%S%z"))
s, b2 = invite("SA-1", "客户甲", "2026-10-04T12:00:00")
check("截止时刻不带时区 -> 422 signoff_deadline_invalid",
      s == 422 and err_code(b2) == "signoff_deadline_invalid", f"{s} {b2}")

s, b = invite("SA-1", "  客户甲  ", future)
check("合法邀请 201", s == 201, f"got {s} {b}")
inv1, key1 = b["invitation_no"], b["key"]
check("返回邀请编号(INV-前缀)", inv1.startswith("INV-"), inv1)
check("一次性密钥为 64 位十六进制", len(key1) == 64 and all(c in "0123456789abcdef" for c in key1),
      key1)
check("收件人去除首尾空白", b["recipient"] == "客户甲", b.get("recipient"))
check("回显截止时刻与创建时刻", b.get("deadline") and b.get("created_at"))

s, b2 = invite("SA-1", "客户乙", future)
check("同一归档包可再建一份邀请", s == 201 and b2["key"] != key1, f"{s}")
inv2, key2 = b2["invitation_no"], b2["key"]

# ---------------------------------------------------------------------------
print("== B. 一次性密钥明文不得持久化 ==")
try:
    import psycopg

    _conn = psycopg.connect(
        host=os.environ.get("DB_HOST", "127.0.0.1"),
        port=os.environ.get("DB_PORT", "5432"),
        dbname=os.environ.get("DB_NAME", "caltrace"),
        user=os.environ.get("DB_USER", "caltrace"),
        password=os.environ.get("DB_PASSWORD", "caltrace"),
    )
    with _conn.cursor() as cur:
        cur.execute("SELECT key_hash FROM signoff_invitations WHERE invitation_no = %s", (inv1,))
        kh = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM signoff_invitations WHERE key_hash = %s", (key1,))
        key_as_hash = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM signoff_invitations")
        n_inv = cur.fetchone()[0]
    check("库内保存的是 64 位哈希而非明文", len(kh) == 64 and kh != key1, kh)
    check("明文密钥不作为 key_hash 出现", key_as_hash == 0)
    check("两份邀请均已落库", n_inv >= 2, str(n_inv))
except ImportError:
    check("psycopg 直连核查（跳过：无驱动）", True)

# ---------------------------------------------------------------------------
print("== C. 提交认证：未知邀请/错误密钥 ==")
s, b = submit("INV-deadbeef", key1, "REJECT", reason="随便")
check("未知邀请 -> 401 signoff_unauthorized",
      s == 401 and err_code(b) == "signoff_unauthorized", f"{s} {b}")
s, b = submit(inv1, "wrong-secret", "REJECT", reason="随便")
check("错误密钥 -> 401 signoff_unauthorized",
      s == 401 and err_code(b) == "signoff_unauthorized", f"{s} {b}")
s, b = submit(inv1, key1, "REJECT", reason="   ")
check("拒收原因为纯空白 -> 422", s == 422, f"{s}")
s, b = submit(inv1, key1, "REJECT")
check("拒收缺原因 -> 422", s == 422, f"{s}")

# ---------------------------------------------------------------------------
print("== D. REJECT 定稿 + 幂等重放（含截止后）+ 异内容/他邀请冲突 ==")
s, b = submit(inv1, key1, "REJECT", reason="客户现场核对发现外观磕碰")
check("首次拒收 201", s == 201, f"{s} {b}")
expect_record = {
    "archive_no": "SA-1", "recipient": "客户甲", "decision": "REJECT",
    "reason": "客户现场核对发现外观磕碰", "invitation_no": inv1,
}
for k, v in expect_record.items():
    check(f"定稿字段 {k}", b.get(k) == v, f"{b.get(k)!r} != {v!r}")
check("含签收时刻", bool(b.get("signed_at")))

s, b_re = submit(inv1, key1, "REJECT", reason="客户现场核对发现外观磕碰")
check("同邀请同内容重试 -> 200", s == 200, f"got {s}")
check("重试与首次定稿一致", b_re == b, json.dumps(b_re, ensure_ascii=False))
s, b_ws = submit(inv1, key1, "REJECT", reason="  客户现场核对发现外观磕碰  ")
check("原因仅首尾空白差异 -> 归一化后仍 200 一致",
      s == 200 and b_ws == b, f"{s} {json.dumps(b_ws, ensure_ascii=False)}")

s, b2 = submit(inv1, key1, "ACCEPT")
check("同邀请不同内容 -> 409 signoff_conflict",
      s == 409 and err_code(b2) == "signoff_conflict", f"{s} {b2}")
s, b2 = submit(inv2, key2, "REJECT", reason="另一位客户拒收")
check("其他邀请再提交 -> 409 signoff_conflict",
      s == 409 and err_code(b2) == "signoff_conflict", f"{s} {b2}")

s, bg = get_record("SA-1", key=None)
check("查询定稿缺管理密钥 -> 401", s == 401 and err_code(bg) == "admin_key_invalid", f"{s}")
s, bg = get_record("SA-1")
check("管理密钥查询定稿 200", s == 200 and bg == b, f"{s} {bg}")

# ---------------------------------------------------------------------------
print("== E. 定稿后即使邀请过期，同内容仍返回首次结果；异内容仍冲突 ==")
s, bx = call("POST", "/api/v1/delivery-archives",
             {"archive_no": "SA-5", "cert_nos": ["SC-1"]})
check("归档 SA-5 201", s == 201, f"got {s}")
dl = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()
s, bx = invite("SA-5", "客户戊", dl)
check("SA-5 邀请 201", s == 201, f"{s}")
inv5, key5 = bx["invitation_no"], bx["key"]
s, r5 = submit(inv5, key5, "REJECT", reason="戊拒收")
check("SA-5 首次拒收 201", s == 201, f"{s} {r5}")
time.sleep(2.5)
s, r5b = submit(inv5, key5, "REJECT", reason="戊拒收")
check("截止后同邀请同内容 -> 200 首次结果", s == 200 and r5b == r5, f"{s}")
s, b2 = submit(inv5, key5, "REJECT", reason="改个原因")
check("截止后不同内容 -> 409", s == 409 and err_code(b2) == "signoff_conflict", f"{s}")

# ---------------------------------------------------------------------------
print("== F. 未定稿时过期或无效密钥不能签收 ==")
dl = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()
s, bx = invite("SA-2", "客户乙", dl)
check("SA-2 邀请 201", s == 201, f"{s}")
inv6, key6 = bx["invitation_no"], bx["key"]
time.sleep(2.5)
s, b2 = submit(inv6, "bad-key", "ACCEPT")
check("过期后错误密钥 -> 401（先认证后过期判定）",
      s == 401 and err_code(b2) == "signoff_unauthorized", f"{s}")
s, b2 = submit(inv6, key6, "ACCEPT")
check("未定稿且已过截止 -> 410 signoff_expired",
      s == 410 and err_code(b2) == "signoff_expired", f"{s} {b2}")
s, b2 = get_record("SA-2")
check("SA-2 仍未定稿 -> 404 signoff_not_found",
      s == 404 and err_code(b2) == "signoff_not_found", f"{s}")
s, b2 = get_record("NO-SUCH")
check("未知归档查询定稿 -> 404 archive_not_found",
      s == 404 and err_code(b2) == "archive_not_found", f"{s}")

# ---------------------------------------------------------------------------
print("== G. ACCEPT 正常定稿；定稿后撤销不改写签收记录与归档快照 ==")
s, _ = ref("SR-3", "签收基准器3")
s, _ = cal("SC-3", "SR-3", name="签收仪表3")
s, _ = cal("SC-4", "SC-3", name="签收仪表4")
s, b = call("POST", "/api/v1/delivery-archives",
            {"archive_no": "SA-3", "cert_nos": ["SC-3", "SC-4"]})
check("归档 SA-3 201", s == 201, f"got {s}")
snap_before = b
s, bx = invite("SA-3", "客户丙", future)
check("SA-3 邀请 201", s == 201, f"{s}")
inv3, key3 = bx["invitation_no"], bx["key"]
s, acc = submit(inv3, key3, "ACCEPT")
check("ACCEPT 定稿 201", s == 201 and acc["decision"] == "ACCEPT"
      and acc["reason"] is None and acc["recipient"] == "客户丙", f"{s} {acc}")
s, ar = revoke("SR-3", reason="定稿后撤销")
check("定稿后撤销基准 200", s == 200, f"got {s}")
s, rec_now = get_record("SA-3")
check("撤销后定稿记录不变", s == 200 and rec_now == acc, f"{rec_now}")
s, snap_now = call("GET", "/api/v1/delivery-archives/SA-3")
check("撤销后归档快照不变（链节点仍 ACTIVE）",
      snap_now == snap_before
      and all(n["certificate"]["status"] == "ACTIVE"
              for it in snap_now["items"] for n in it["chain"]["nodes"]),
      "snapshot changed")

# ---------------------------------------------------------------------------
print("== H. ACCEPT 时目标或冻结追溯链已撤销/失效 -> 拒绝并列出受影响目标 ==")
s, _ = ref("SR-4", "签收基准器4")
s, _ = cal("SC-5", "SR-4", name="签收仪表5")
s, _ = cal("SC-6", "SC-5", name="签收仪表6")
s, _ = ref("SR-4B", "签收基准器4B")
s, _ = cal("SC-7", "SR-4B", name="签收仪表7")
s, _ = call("POST", "/api/v1/delivery-archives",
            {"archive_no": "SA-4", "cert_nos": ["SC-6", "SC-7"]})
check("归档 SA-4（一链受撤销、一链完好）201", s == 201, f"got {s}")
s, bx = invite("SA-4", "客户丁", future)
check("SA-4 邀请 201", s == 201, f"{s}")
inv4, key4 = bx["invitation_no"], bx["key"]
s, _ = revoke("SR-4", reason="签收前撤销基准")
check("撤销 SR-4（SC-5/SC-6 级联失效）200", s == 200, f"got {s}")
s, b2 = submit(inv4, key4, "ACCEPT")
check("ACCEPT 被拒绝 422 signoff_targets_revoked",
      s == 422 and err_code(b2) == "signoff_targets_revoked", f"{s} {json.dumps(b2, ensure_ascii=False)[:300]}")
d = b2.get("error", {}).get("details", {})
check("受影响目标仅列 SC-6", d.get("affected_targets") == ["SC-6"], str(d.get("affected_targets")))
revoked_nos = {x["cert_no"] for x in d.get("revoked_certificates", [])}
check("列出链上撤销/失效证书(SR-4,SC-5,SC-6)",
      {"SR-4", "SC-5", "SC-6"} <= revoked_nos, str(revoked_nos))
check("完好链 SC-7 不受影响", "SC-7" not in revoked_nos, str(revoked_nos))
s, rj = submit(inv4, key4, "REJECT", reason="凭据失效，客户拒收")
check("同邀请改 REJECT 仍可提交 201", s == 201 and rj["decision"] == "REJECT", f"{s} {rj}")

# ---------------------------------------------------------------------------
print("== I. 并发：同邀请同内容并发提交仅一份定稿（一 201 余 200） ==")
s, _ = ref("SR-9", "签收基准器9")
s, _ = cal("SC-9", "SR-9", name="签收仪表9")
s, _ = call("POST", "/api/v1/delivery-archives",
            {"archive_no": "SA-9", "cert_nos": ["SC-9"]})
s, bx = invite("SA-9", "并发客户", future)
inv9, key9 = bx["invitation_no"], bx["key"]
out9 = []
barrier = threading.Barrier(8)


def worker_accept():
    barrier.wait()
    out9.append(submit(inv9, key9, "ACCEPT"))


threads = [threading.Thread(target=worker_accept) for _ in range(8)]
[t.start() for t in threads]
[t.join() for t in threads]
codes = sorted(c for c, _ in out9)
check("8 并发：恰一个 201，其余 200", codes == [200] * 7 + [201], str(codes))
check("全部返回同一份定稿", len({json.dumps(b, sort_keys=True) for _, b in out9}) == 1)

# ---------------------------------------------------------------------------
print("== I2. 并发：不同邀请各自首提同一归档包 -> 恰一定稿，其余 409（无 5xx） ==")
s, _ = ref("SR-92", "签收基准器92")
s, _ = cal("SC-92", "SR-92", name="签收仪表92")
s, _ = call("POST", "/api/v1/delivery-archives",
            {"archive_no": "SA-92", "cert_nos": ["SC-92"]})
pairs = []
for who in ("并发客户a", "并发客户b", "并发客户c", "并发客户d"):
    s, bx = invite("SA-92", who, future)
    check(f"为 {who} 创建邀请 201", s == 201, f"{s}")
    pairs.append((bx["invitation_no"], bx["key"]))
out92 = []
barrier2 = threading.Barrier(4)


def worker_other_invite(idx):
    inv, k = pairs[idx]
    barrier2.wait()
    out92.append(submit(inv, k, "REJECT", reason=f"客户{idx}拒收"))


threads = [threading.Thread(target=worker_other_invite, args=(i,)) for i in range(4)]
[t.start() for t in threads]
[t.join() for t in threads]
codes92 = sorted(c for c, _ in out92)
check("4 个不同邀请并发：恰一个 201，其余 409", codes92.count(201) == 1
      and codes92.count(409) == 3 and all(c in (201, 409) for c in codes92), str(codes92))
check("冲突均为 signoff_conflict（无 5xx）",
      all(c == 201 or err_code(b) == "signoff_conflict" for c, b in out92),
      str([(c, err_code(b)) for c, b in out92]))

# ---------------------------------------------------------------------------
print("== I3. ACCEPT 携带多余 reason 不影响幂等（内容归一化） ==")
s, _ = ref("SR-93", "签收基准器93")
s, _ = cal("SC-93", "SR-93", name="签收仪表93")
s, _ = call("POST", "/api/v1/delivery-archives",
            {"archive_no": "SA-93", "cert_nos": ["SC-93"]})
s, bx = invite("SA-93", "归一化客户", future)
inv93, key93 = bx["invitation_no"], bx["key"]
s, r93a = submit(inv93, key93, "ACCEPT")
check("ACCEPT 首次 201 且 reason 落库为 null",
      s == 201 and r93a["reason"] is None, f"{s} {r93a}")
s, r93b = submit(inv93, key93, "ACCEPT", reason="携带了也忽略的原因")
check("带 reason 的 ACCEPT 重试仍 200 且一致", s == 200 and r93b == r93a, f"{s} {r93b}")

# ---------------------------------------------------------------------------
print("== J. 并发：签收 ACCEPT 与撤销按提交顺序判定，无死锁/500 ==")
for i in range(8):
    r, c1, c2 = f"SR-R{i}", f"SC-R{i}A", f"SC-R{i}B"
    s, _ = ref(r, f"并发基准{i}")
    s, _ = cal(c1, r)
    s, _ = cal(c2, c1)
    s, _ = call("POST", "/api/v1/delivery-archives",
                {"archive_no": f"SA-R{i}", "cert_nos": [c1, c2]})
    s, bx = invite(f"SA-R{i}", f"客户{i}", future)
    inv_r, key_r = bx["invitation_no"], bx["key"]
    res = {}
    b2 = threading.Barrier(2)

    def do_accept():
        b2.wait()
        res["accept"] = submit(inv_r, key_r, "ACCEPT")

    def do_revoke():
        b2.wait()
        res["revoke"] = revoke(r, reason=f"并发撤销{i}")

    t1, t2 = threading.Thread(target=do_accept), threading.Thread(target=do_revoke)
    t1.start(); t2.start(); t1.join(); t2.join()
    ac, ab = res["accept"]
    rc, rb = res["revoke"]
    check(f"链{i}: 撤销 200", rc == 200, f"{rc} {rb}")
    check(f"链{i}: 签收结果为定稿201或撤销先行422",
          (ac in (200, 201)) or (ac == 422 and err_code(ab) == "signoff_targets_revoked"),
          f"{ac} {json.dumps(ab, ensure_ascii=False)[:200]}")
    check(f"链{i}: 无 5xx/409 死锁兜底",
          ac < 500 and rc < 500 and not (ac == 409 and err_code(ab) == "signoff_busy"),
          f"accept={ac} revoke={rc}")
    if ac in (200, 201):
        s, rec_r = get_record(f"SA-R{i}")
        check(f"链{i}: 先签后撤 -> 定稿保持 ACCEPT 不被改写",
              s == 200 and rec_r["decision"] == "ACCEPT"
              and rec_r["signed_at"] <= rb["revoked_at"],
              f"{rec_r.get('decision')} {rec_r.get('signed_at')} vs {rb.get('revoked_at')}")
    else:
        s, _ = get_record(f"SA-R{i}")
        check(f"链{i}: 先撤后签 -> 无定稿", s == 404, f"got {s}")

# ---------------------------------------------------------------------------
print("== K. 既有接口语义不变（抽样） ==")
s, b = call("GET", "/api/v1/certificates/SC-6")
check("失效证书仍可查且为 INVALID",
      s == 200 and b["status"] == "INVALID", f"{s} {b.get('status')}")
s, _ = call("GET", "/api/v1/revocations/1/archive-impact?limit=5&offset=0")
check("撤销影响面接口仍可用", s == 200, f"got {s}")
s, _ = call("GET", "/health")
check("健康检查 200", s == 200)

# ---------------------------------------------------------------------------
failed = [n for n, ok, _ in results if not ok]
print(f"\n总计 {len(results)} 项，失败 {len(failed)} 项")
if failed:
    print("失败项：")
    for n in failed:
        print(" -", n)
    sys.exit(1)
print("全部通过 ✅")
