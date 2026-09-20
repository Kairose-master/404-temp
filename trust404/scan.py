# Canonical scanner (single source of truth).
# agent/scanner.py and api/prove.py delegate here.
# TRUST404 Track04 — static scanner.
# 타깃 소스를 정규식/패턴으로 훑어 (a) 취약 유형별 점수와 (b) 템플릿 파라미터화에
# 필요한 함수 시그니처를 추출한다. 특정 타깃 이름을 하드코딩하지 않는다 —
# 공개셋에 없는 비공개 타깃에도 같은 패턴 규칙이 적용되게 한다.
import re

FAM_REENTRANCY = "reentrancy"
FAM_ACCESS = "access_control"
FAM_INTEGER = "integer_underflow"
FAM_ORACLE = "oracle_manipulation"
# Families drawn from the classic contract wargames (Ethernaut, Damn
# Vulnerable DeFi, Capture the Ether) and the SoK vulnerability taxonomies.
FAM_DELEGATECALL = "delegatecall_hijack"   # Ethernaut Delegation/Preservation, Parity
FAM_RANDOMNESS = "weak_randomness"         # Ethernaut CoinFlip, CTE Predict-the-Future
FAM_INIT = "unprotected_init"              # Ethernaut Motorbike, uninitialized proxies

# On-chain entropy sources that are fully known to the caller in-transaction —
# using any of these to gate a payout is exploitable (predictable RNG).
_ENTROPY_TOKENS = (
    "block.timestamp", "block.prevrandao", "block.difficulty",
    "block.number", "blockhash", "block.coinbase", "block.gaslimit",
)


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


STRATEGY_ORDER = [
    FAM_REENTRANCY, FAM_ACCESS, FAM_INTEGER, FAM_ORACLE,
    FAM_DELEGATECALL, FAM_RANDOMNESS, FAM_INIT,
]


def _contract_bodies(src):
    """{contractName: body} — brace-matched contract bodies."""
    out = {}
    for mm in re.finditer(r"\bcontract\s+(\w+)", src):
        bi = src.find("{", mm.end())
        if bi < 0:
            continue
        out[mm.group(1)] = _extract_block(src, bi)
    return out


_PRIVILEGED_NAME = (
    r"(?:owner|admin|administrator|governor|governance|guardian|operator|"
    r"manager|controller|authority|authorized|maintainer|upgrader|role|"
    r"minter|pauser|proposer|executor|keeper)"
)
_PRIVILEGED_WRITE = re.compile(
    rf"\b({_PRIVILEGED_NAME})\b\s*=", re.I
)
_INIT_NAME = re.compile(r"^(?:initialize|init|initializer|__init)\w*$", re.I)


def _has_privilege_guard(fn, src):
    """Recognize common owner/admin/role gates on an externally callable path."""
    head = fn.get("head", "")
    body = fn.get("body", "")
    if re.search(
        r"\b(?:only(?:owner|admin|administrator|governor|governance|guardian|"
        r"operator|manager|controller|authority|authorized|maintainer|upgrader|"
        r"role|minter|pauser|proposer|executor|keeper)\w*|auth(?:orized)?|"
        r"requiresAuth)\b",
        head, re.I,
    ):
        return True
    privileged = _PRIVILEGED_NAME
    if re.search(rf"require\s*\(\s*msg\.sender\s*==\s*\w*{privileged}\w*\b", body, re.I):
        return True
    if re.search(rf"require\s*\(\s*\w*{privileged}\w*\s*==\s*msg\.sender\b", body, re.I):
        return True
    if re.search(rf"if\s*\(\s*msg\.sender\s*!=\s*\w*{privileged}\w*\s*\)\s*revert", body, re.I):
        return True
    if re.search(r"(?:hasRole|_checkRole)\s*\([^;{}]*msg\.sender", body):
        return True
    if re.search(r"(?:authorized|isAdmin|isOwner|operators?)\s*\[\s*msg\.sender\s*\]", body, re.I):
        return True
    return False


def _has_owner_guard(fn, src):
    """Backward-compatible name used by the older API surface."""
    return _has_privilege_guard(fn, src)


def _has_reentrancy_guard(fn):
    head = fn.get("head", "")
    body = fn.get("body", "")
    if re.search(r"\bnonReentrant\b|\breentrancyGuard\b", head, re.I):
        return True
    return bool(
        re.search(r"require\s*\(\s*!?\s*\w*(?:lock|entered|status)\w*", body, re.I)
        and re.search(r"\b\w*(?:lock|entered|status)\w*\s*=", body, re.I)
    )


def _reentrancy_vulnerable(fn, src=""):
    """Return true for a concrete caller-ledger CEI violation.

    A payout alone is not reentrancy evidence. The function must pay the
    caller, read that caller's ledger before the call, and clear/decrement the
    same ledger only after the call, without a mutex on the entry point.
    """
    if not fn.get("external") or _has_reentrancy_guard(fn):
        return False
    body = fn.get("body", "")
    call = re.search(
        r"(?:payable\s*\(\s*)?msg\.sender(?:\s*\))?\s*\.\s*call\s*"
        r"\{\s*value\s*:",
        body,
    )
    if not call:
        return False
    before, after = body[:call.start()], body[call.end():]
    ledgers = set(re.findall(r"\b(\w+)\s*\[\s*msg\.sender\s*\]", before))
    for ledger in ledgers:
        slot = rf"\b{re.escape(ledger)}\s*\[\s*msg\.sender\s*\]"
        effect = rf"(?:{slot}\s*(?:=\s*0|-=)|delete\s+{slot})"
        if not re.search(effect, before) and re.search(effect, after):
            return True
    return False


def _attacker_controlled_value_call(fn):
    """Identify an unguarded administrative drain, not an ordinary payout."""
    body = fn.get("body", "")
    address_args = {name for typ, name in fn.get("args", []) if typ == "address" and name}
    uint_args = {name for typ, name in fn.get("args", []) if typ.startswith("uint") and name}
    privileged_name = bool(re.search(
        r"(?:admin|emergency|sweep|rescue|recover|drain|withdrawAll)",
        fn.get("name", ""), re.I,
    ))
    for call in re.finditer(
        r"(?P<receiver>(?:payable\s*\([^)]*\)|[A-Za-z_]\w*|msg\.sender))\s*"
        r"\.\s*call\s*\{\s*value\s*:\s*(?P<value>[^}]+)\}",
        body,
    ):
        receiver, value = call.group("receiver"), call.group("value")
        receiver_controlled = any(re.search(rf"\b{re.escape(arg)}\b", receiver)
                                  for arg in address_args)
        amount_controlled = any(re.search(rf"\b{re.escape(arg)}\b", value)
                                for arg in uint_args)
        full_balance = bool(re.search(
            r"(?:address\s*\(\s*this\s*\)|this)\s*\.\s*balance", value))
        if (receiver_controlled and amount_controlled) or full_balance or privileged_name:
            return True
    return False


def scan_target(contract_src, invariants_src, manifest):
    src = _strip_comments(contract_src)
    fns = _functions(src)
    scores = {
        FAM_REENTRANCY: 0, FAM_ACCESS: 0, FAM_INTEGER: 0, FAM_ORACLE: 0,
        FAM_DELEGATECALL: 0, FAM_RANDOMNESS: 0, FAM_INIT: 0,
    }
    sig = {"functions": fns}

    # ── Reentrancy ────────────────────────────────────────────────────────────
    # Require a concrete caller-ledger CEI violation. Lottery payouts and
    # guarded/CEI-compliant withdrawals are not attack candidates.
    for fn in fns:
        if _reentrancy_vulnerable(fn, src):
            scores[FAM_REENTRANCY] += 5
            sig.setdefault("reentrancy_withdraw", fn)
    # a payable deposit that credits msg.sender (any ledger name) — needed for the PoC
    for fn in fns:
        if fn["payable"] and re.search(r"\w+\[\s*msg\.sender\s*\]\s*\+=\s*msg\.value", fn["body"]):
            sig.setdefault("reentrancy_deposit", fn)

    # ── Access control ────────────────────────────────────────────────────────
    for fn in fns:
        if not fn["external"]:
            continue
        b = fn["body"]
        sets_privilege = bool(_PRIVILEGED_WRITE.search(b)) and not _INIT_NAME.match(fn["name"])
        moves_value = _attacker_controlled_value_call(fn)
        if (moves_value or sets_privilege) and not _has_privilege_guard(fn, src):
            scores[FAM_ACCESS] += 5
            if moves_value:
                sig["access_drain"] = fn
            if sets_privilege:
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

    # ── Delegatecall hijack ───────────────────────────────────────────────────
    # A function that delegatecalls an address it received as a PARAMETER runs
    # attacker code in this contract's storage → owner/admin (slot 0) can be
    # overwritten. Delegatecall to an immutable/state module is not attacker-
    # controlled and is not flagged (LibraryVault stays safe).
    for fn in fns:
        if not fn["external"]:
            continue
        b = fn["body"]
        m = re.search(r"(\w+)\s*\.\s*delegatecall\s*\(", b)
        if not m:
            continue
        receiver = m.group(1)
        addr_params = [an for (t, an) in fn["args"] if t == "address"]
        has_bytes = any(t.startswith("bytes") for t, _ in fn["args"])
        if receiver in addr_params:
            # attacker supplies the delegatecall target
            scores[FAM_DELEGATECALL] += 5
            sig["delegatecall_entry"] = {"fn": fn, "receiver": receiver, "has_bytes": has_bytes}
        # receiver is a state var / immutable → not attacker-controlled → no score

    # ── Weak / predictable randomness ─────────────────────────────────────────
    # A payout gated on an on-chain entropy source the caller can read in the
    # same tx is exploitable: the attacker computes the identical value and
    # always wins. Require (entropy source) AND (keccak256 or modulo mixing)
    # AND (a value transfer) in the same function, so a mere block.timestamp
    # deadline check does not trip it.
    for fn in fns:
        if not fn["external"]:
            continue
        b = fn["body"]
        has_entropy = any(tok in b for tok in _ENTROPY_TOKENS)
        mixes = ("keccak256" in b) or ("%" in b)
        transfers = bool(re.search(r"\.call\s*\{\s*value\s*:", b)) or \
            bool(re.search(r"balance[sfO]?\w*\[[^\]]+\]\s*\+=", b))
        if has_entropy and mixes and transfers:
            scores[FAM_RANDOMNESS] += 5
            sig["randomness_fn"] = fn

    # ── Unprotected initializer ───────────────────────────────────────────────
    # An initializer that sets owner/admin with neither an `initialized` guard
    # nor access control lets the first caller seize the contract. A guarded
    # initializer (require(!initialized) / initializer modifier) is safe.
    for fn in fns:
        if not fn["external"]:
            continue
        b = fn["body"]
        head = fn["head"]
        looks_init = bool(_INIT_NAME.match(fn["name"]))
        sets_privilege_to_sender = bool(
            re.search(r"\b(owner|admin)\b\s*=\s*msg\.sender", b))
        sets_privilege_to_param = bool(
            re.search(r"\b(owner|admin)\b\s*=\s*\w+", b)) and looks_init
        guarded = bool(
            re.search(r"require\s*\(\s*!\s*\w*[Ii]nitialized", b)
            or re.search(r"\binitializer\b", head)
            or "_disableInitializers" in src
            or _has_owner_guard(fn, src))
        if (looks_init or sets_privilege_to_sender) and \
           (sets_privilege_to_sender or sets_privilege_to_param) and not guarded:
            scores[FAM_INIT] += 5
            sig["init_fn"] = fn

    sig["scores"] = scores
    sig["src"] = src
    sig["invariant_predicates"] = manifest.get("invariants", {}).get("predicates", [])
    return sig
