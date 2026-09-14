# TRUST404 Track04 — static scanner.
# 타깃 소스를 정규식/패턴으로 훑어 (a) 취약 유형별 점수와 (b) 템플릿 파라미터화에
# 필요한 함수 시그니처를 추출한다. 특정 타깃 이름을 하드코딩하지 않는다 —
# 공개셋에 없는 비공개 타깃에도 같은 패턴 규칙이 적용되게 한다.
import re

FAM_REENTRANCY = "reentrancy"
FAM_ACCESS = "access_control"
FAM_INTEGER = "integer_underflow"
FAM_ORACLE = "oracle_manipulation"


def _strip_comments(src):
    src = re.sub(r"//[^\n]*", "", src)
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return src


def _functions(src):
    """Yield dicts describing each function: name, args(list of (type,name)), mods, body."""
    out = []
    # match `function name(args) visibility modifiers { ... }`
    pat = re.compile(
        r"function\s+(\w+)\s*\(([^)]*)\)([^\{;]*)(\{)", re.S)
    for m in pat.finditer(src):
        name = m.group(1)
        raw_args = m.group(2).strip()
        head = m.group(3)
        body = _extract_block(src, m.end() - 1)
        args = []
        if raw_args:
            for a in raw_args.split(","):
                parts = a.split()
                if not parts:
                    continue
                typ = parts[0]
                an = parts[-1] if len(parts) > 1 else ""
                args.append((typ, an))
        out.append({
            "name": name,
            "args": args,
            "head": head,
            "payable": "payable" in head,
            "external": ("external" in head or "public" in head),
            "body": body,
        })
    return out


def _extract_block(src, brace_idx):
    depth = 0
    i = brace_idx
    n = len(src)
    while i < n:
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[brace_idx + 1:i]
        i += 1
    return src[brace_idx + 1:]


def _has_owner_guard(fn, src):
    b = fn["body"]
    if re.search(r"only\w*[Oo]wner", fn["head"]):
        return True
    if re.search(r"require\s*\(\s*msg\.sender\s*==\s*owner", b):
        return True
    if re.search(r"only\w+", fn["head"]) and "owner" in src.lower():
        # custom modifier referencing owner elsewhere
        return True
    return False


def scan_target(contract_src, invariants_src, manifest):
    src = _strip_comments(contract_src)
    fns = _functions(src)
    scores = {FAM_REENTRANCY: 0, FAM_ACCESS: 0, FAM_INTEGER: 0, FAM_ORACLE: 0}
    sig = {"functions": fns}

    # ── Reentrancy ────────────────────────────────────────────────────────────
    # external call sending value, and state zeroed/decremented AFTER the call
    # (CEI violation), without a reentrancy mutex.
    has_mutex = bool(re.search(r"nonReentrant|locked\s*==\s*1|_status", src))
    for fn in fns:
        b = fn["body"]
        call_m = re.search(r"\.call\s*\{\s*value\s*:", b)
        if not call_m:
            continue
        after = b[call_m.end():]
        zeroes_after = re.search(r"balance[sf]?\w*\[[^\]]+\]\s*(=\s*0|-=)", after)
        pays_sender = re.search(r"call\s*\{\s*value\s*:\s*\w+\s*\}\s*\(\s*\"\"\s*\)", b) or "msg.sender.call" in b
        if zeroes_after and pays_sender:
            scores[FAM_REENTRANCY] += 5
            sig["reentrancy_withdraw"] = fn
    if has_mutex:
        scores[FAM_REENTRANCY] -= 4  # guarded → likely safe
    # a payable deposit that credits msg.sender is required for the classic PoC
    for fn in fns:
        if fn["payable"] and re.search(r"balance[sf]?\w*\[\s*msg\.sender\s*\]\s*\+=\s*msg\.value", fn["body"]):
            sig["reentrancy_deposit"] = fn

    # ── Access control ────────────────────────────────────────────────────────
    for fn in fns:
        if not fn["external"]:
            continue
        b = fn["body"]
        moves_value = re.search(r"\.call\s*\{\s*value\s*:", b)
        sets_owner = re.search(r"\bowner\s*=", b)
        if (moves_value or sets_owner) and not _has_owner_guard(fn, src):
            # ignore the normal user withdraw that checks its own balance
            checks_self_balance = re.search(r"balance[sf]?\w*\[\s*msg\.sender\s*\]", b)
            if moves_value and checks_self_balance and not sets_owner:
                continue
            scores[FAM_ACCESS] += 5
            if moves_value:
                sig["access_drain"] = fn
            if sets_owner:
                sig["access_setowner"] = fn

    # ── Integer underflow ─────────────────────────────────────────────────────
    for m in re.finditer(r"unchecked\s*\{", src):
        blk = _extract_block(src, src.index("{", m.start()))
        if re.search(r"balance[sfO]?\w*\[[^\]]+\]\s*-=", blk):
            scores[FAM_INTEGER] += 5
    # need a redeem/withdraw that pays out `amount` for the drain to matter
    for fn in fns:
        b = fn["body"]
        if re.search(r"\.call\s*\{\s*value\s*:", b) and any(t.startswith("uint") for t, _ in fn["args"]):
            sig["integer_redeem"] = fn
        if re.search(r"balance[sfO]?\w*\[\s*msg\.sender\s*\]\s*-=", b) and len(fn["args"]) >= 2:
            sig["integer_transfer"] = fn

    # ── Oracle manipulation ───────────────────────────────────────────────────
    if re.search(r"spotPrice|getPrice|priceOf|reserve[01A-Za-z]*", src):
        if re.search(r"\bborrow\b", src) and re.search(r"spotPrice|getPrice|reserve", src):
            scores[FAM_ORACLE] += 5
    if re.search(r"\bfaucet\b", src):
        scores[FAM_ORACLE] += 1
    if re.search(r"swap\w*For\w*|swap\s*\(", src):
        scores[FAM_ORACLE] += 1
    for fn in fns:
        if fn["name"] == "borrow":
            sig["oracle_borrow"] = fn
        if fn["name"] == "faucet":
            sig["oracle_faucet"] = fn
        if fn["name"] == "depositCollateral":
            sig["oracle_deposit"] = fn
        if re.match(r"swap\w*For\w*", fn["name"] or ""):
            sig["oracle_swap"] = fn

    sig["scores"] = scores
    sig["invariant_predicates"] = manifest.get("invariants", {}).get("predicates", [])
    return sig
