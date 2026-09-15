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
    scores = {
        FAM_REENTRANCY: 0, FAM_ACCESS: 0, FAM_INTEGER: 0, FAM_ORACLE: 0,
        FAM_DELEGATECALL: 0, FAM_RANDOMNESS: 0, FAM_INIT: 0,
    }
    sig = {"functions": fns}

    # ── Reentrancy ────────────────────────────────────────────────────────────
    # A function that sends value to the caller and does NOT clear the caller's
    # ledger entry BEFORE the external call is a CEI violation — whether the
    # zeroing happens after the call (classic) or in a separate function called
    # afterwards (cross-function reentrancy). Any ledger name is accepted, not
    # just `balance*`. A reentrancy mutex removes the score.
    has_mutex = bool(re.search(r"nonReentrant|locked\s*==\s*1|_status", src))
    # match a caller-ledger clear like `credit[msg.sender] = 0` or `... -=`
    _clear = r"\w+\[\s*msg\.sender\s*\]\s*(=\s*0|-=)"
    for fn in fns:
        b = fn["body"]
        call_m = re.search(r"\.call\s*\{\s*value\s*:", b)
        if not call_m:
            continue
        pays_sender = bool(re.search(r"call\s*\{\s*value\s*:\s*\w+\s*\}\s*\(\s*\"\"\s*\)", b)) or "msg.sender.call" in b
        if not pays_sender:
            continue
        before = b[:call_m.start()]
        cleared_before = re.search(_clear, before)
        if not cleared_before:                 # CEI violated (classic or cross-function)
            scores[FAM_REENTRANCY] += 5
            sig.setdefault("reentrancy_withdraw", fn)
    if has_mutex:
        scores[FAM_REENTRANCY] -= 4  # guarded → likely safe
    # a payable deposit that credits msg.sender (any ledger name) — needed for the PoC
    for fn in fns:
        if fn["payable"] and re.search(r"\w+\[\s*msg\.sender\s*\]\s*\+=\s*msg\.value", fn["body"]):
            sig.setdefault("reentrancy_deposit", fn)

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
    init_name = re.compile(r"^(initialize|init|initializer|__init)\w*$", re.I)
    for fn in fns:
        if not fn["external"]:
            continue
        b = fn["body"]
        head = fn["head"]
        looks_init = bool(init_name.match(fn["name"]))
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
    sig["invariant_predicates"] = manifest.get("invariants", {}).get("predicates", [])
    return sig
