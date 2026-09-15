"""Feature-gated provider table.

Former Ethernaut *level solvers* live in api/prove.py as `_synth_*`. This
module does not import them (that would pull solc at import time). It names
them and declares which capability tags they need, so `iter_engine_candidates`
can skip compile/deploy when the source cannot possibly match.

`needs` is an OR-set: any overlapping feature is enough. This keeps
generalization wide (a gasleft%N gate on an unnamed contract still fires
the Gatekeeper-One *family*) while dropping SafeVault-style false work.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Iterable, List, Optional, Set


@dataclass(frozen=True)
class Provider:
    fn_name: str
    family: str          # generalized family, NOT a level name
    stage: str           # "synth" | "fuzz"
    needs: FrozenSet[str]
    note: str


# Keep in lockstep with the `for fn in (...)` list in api/prove.py
# iter_engine_candidates. Adding a synth without a row here means "always run".
PROVIDERS: List[Provider] = [
    Provider("_storage_attempt", "private_slot_oracle", "synth",
             frozenset({"private_unlock", "bytes32_secret"}),
             "private 슬롯을 읽어 게이트를 여는 계열 (Vault/Privacy 일반화)"),
    Provider("_proxy_attempt", "fallback_delegatecall_proxy", "synth",
             frozenset({"fallback_delegatecall", "delegatecall_param"}),
             "fallback→delegatecall 배선 (Delegation 일반화)"),
    Provider("_multiblock_attempt", "block_entropy_runner", "synth",
             frozenset({"block_entropy"}),
             "블록 엔트로피 복제 다중 블록 러너 (CoinFlip 일반화)"),
    Provider("_synth_storage_collision", "delegatecall_slot_collision", "synth",
             frozenset({"delegatecall_stored_lib"}),
             "저장된 라이브러리 포인터 delegatecall 2단계 충돌 (Preservation 일반화)"),
    Provider("_synth_king_dos", "push_payment_griefing", "synth",
             frozenset({"push_refund_role"}),
             "push refund 로 특권 역할을 영구 락 (King 일반화)"),
    Provider("_synth_callback_inconsistency", "view_callback_inconsistency", "synth",
             frozenset({"view_callback_twice", "view_price_callback"}),
             "외부 view 콜백을 두 번 신뢰 (Elevator/Shop 일반화)"),
    Provider("_synth_shop", "view_price_inconsistency", "synth",
             frozenset({"view_price_callback"}),
             "price() 이중 호출 조작"),
    Provider("_synth_lockup_bypass", "alternate_transfer_path", "synth",
             frozenset({"approve_transferFrom", "lockup"}),
             "락업된 transfer 를 approve+transferFrom 으로 우회 (NaughtCoin 일반화)"),
    Provider("_synth_gas_griefing", "unbounded_callback_dos", "synth",
             frozenset({"withdraw_to_partner", "unbounded_loop"}),
             "수신자 콜백 가스 소진 DoS (Denial 일반화)"),
    Provider("_synth_force", "forced_ether", "synth",
             frozenset({"no_receive", "selfdestruct"}),
             "selfdestruct 강제 ETH 주입 (Force 일반화)"),
    Provider("_synth_gatekeeper_two", "constructor_extcodesize_gate", "synth",
             frozenset({"extcodesize_zero", "xor_extcodehash_key"}),
             "생성자 호출(extcodesize=0) + XOR 키 (Gatekeeper Two 일반화)"),
    Provider("_synth_gatekeeper_one", "gas_modulo_origin_gate", "synth",
             frozenset({"gasleft_modulo", "tx_origin_mask"}),
             "gasleft()%N 브루트포스 + tx.origin 키 (Gatekeeper One 일반화)"),
    Provider("_synth_magicnumber", "runtime_bytecode_constraint", "synth",
             frozenset({"solver_size_gate"}),
             "런타임 바이트코드 크기 제약 solver"),
    Provider("_synth_higher_order", "calldata_width_confusion", "synth",
             frozenset({"calldata_fullword_sstore", "narrow_abi_param"}),
             "좁은 ABI 타입 vs 전체 calldataload sstore (HigherOrder 일반화)"),
    Provider("_synth_switch", "calldata_offset_selector_check", "synth",
             frozenset({"selector_offset_check"}),
             "고정 오프셋 셀렉터 검사를 calldata 배치로 우회 (Switch 일반화)"),
    Provider("_synth_array_underflow", "storage_array_underflow", "synth",
             frozenset({"array_length_unchecked"}),
             "동적 배열 length 언더플로 → 슬롯 0 기록 (AlienCodex 일반화)"),
    Provider("_synth_dex_two_drain", "unverified_token_swap", "synth",
             frozenset({"swap_unverified_token", "dex_spot_swap"}),
             "토큰 미검증 스왑 (DexTwo 일반화)"),
    Provider("_synth_dex_drain", "spot_amm_drain", "synth",
             frozenset({"dex_spot_swap", "spot_price", "swap"}),
             "스팟 가격 반복 스왑으로 풀 소진 (Dex 일반화)"),
    Provider("_synth_good_samaritan", "callback_error_drain", "synth",
             frozenset({"custom_error_catch"}),
             "커스텀 에러 catch → remainder 인출 (GoodSamaritan 일반화)"),
    Provider("_synth_eip7702_reentrancy", "origin_gated_hook_reentrancy", "synth",
             frozenset({"tx_origin_eoa_gate", "receiver_hook_before_mint", "receiver_hook"}),
             "tx.origin EOA 게이트 + 민트 전 수신자 훅 (EIP-7702 일반화)"),
    Provider("_synth_gatekeeper_three", "typo_init_and_send_gate", "synth",
             frozenset({"construct0r", "send_gate", "unguarded_initialize"}),
             "오타 initializer + send 게이트 (Gatekeeper Three 일반화)"),
    Provider("_synth_stake_accounting", "fake_token_accounting", "synth",
             frozenset({"fake_weth", "stake"}),
             "가짜 ERC20 회계로 실자산 인출 (Stake 일반화)"),
    Provider("_synth_uninitialized", "unguarded_initializer", "synth",
             frozenset({"unguarded_initialize"}),
             "미보호 initialize 로 특권 선점 (Motorbike 일반화)"),
    Provider("_synth_puzzle_wallet", "proxy_wallet_slot_collision", "synth",
             frozenset({"proxy_admin", "nested_multicall", "slot_alias_max_balance"}),
             "프록시/구현 슬롯 충돌 + 중첩 multicall (PuzzleWallet 일반화)"),
    Provider("_synth_ecdsa_malleability", "ecdsa_s_malleability", "synth",
             frozenset({"ecrecover"}),
             "ecrecover s-malleability (Impersonator 일반화)"),
    Provider("_synth_magic_carousel", "packed_storage_overflow", "synth",
             frozenset({"packed_id_overflow", "packed_storage_write"}),
             "패킹된 슬롯에 사용자 바이트가 포인터 필드로 흘러감 (Carousel 일반화)"),
    Provider("_synth_commitment_collision", "commitment_off_by_one", "synth",
             frozenset({"commit_hash_loop"}),
             "커밋 해시 루프 off-by-one"),
    # DVD / CTF / incident families — implemented in trust404.synth_defi
    Provider("unpermissioned_callback", "unpermissioned_callback", "synth",
             frozenset({"unpermissioned_callback"}),
             "무허가 calldata/target 콜백 (Truster, AtomicQueue 2026-09)"),
    Provider("donation_accounting_dos", "donation_accounting_dos", "synth",
             frozenset({"donation_accounting_dos"}),
             "토큰 기부로 내부 회계 assert 깨기 (Unstoppable)"),
    Provider("governance_flashloan", "governance_flashloan", "synth",
             frozenset({"governance_flashloan"}),
             "플래시론으로 거버넌스 스냅샷 (Selfie)"),
    Provider("execute_before_schedule", "execute_before_schedule", "synth",
             frozenset({"execute_before_schedule"}),
             "execute 후 schedule 검사 (Climber timelock)"),
    Provider("twap_as_spot", "twap_as_spot", "synth",
             frozenset({"twap_oracle", "twap_falls_to_spot"}),
             "한 run() 안에서 스팟으로 붕괴하는 TWAP (Puppet v1/가짜 v3)"),
    Provider("twap_window", "twap_window", "synth",
             frozenset({"windowed_twap"}),
             "Observation[] 윈도우: skew → warp → borrow (HEVM / phased)"),
    Provider("cross_getter_drain", "cross_getter_drain", "synth",
             frozenset({"sibling_getter", "multi_contract_unit", "address_ctor"}),
             "public getter 로 형제 컨트랙트 주소 회수 후 drain"),
    Provider("victim_approve", "victim_approve", "synth",
             frozenset({"victim_approve", "victim_getter"}),
             "피해자 approve 선행 (prank / 두번째 EOA)"),
    Provider("seeded_allowance_drain", "seeded_allowance_drain", "synth",
             frozenset({"setup_seeded_allowance", "victim_getter"}),
             "Setup/world.txs 가 이미 approve 한 잔여 승인 drain (치트코드 없음)"),
    Provider("cross_chain_bridge", "cross_chain_bridge", "synth",
             frozenset({"cross_chain_bridge"}),
             "같은 EVM 안의 메신저/LZ/OP relay 콜백"),
]

_BY_FN = {p.fn_name: p for p in PROVIDERS}


def should_run(fn_name: str, features: Optional[Set[str]]) -> bool:
    """If features is None (extractor failed), run everything.

    Unknown fn_name → run (forward-compat). Empty feature set → skip
    specialized synths (they cannot match) but that is the caller's choice;
    we return False when needs ∩ features is empty.
    """
    if features is None:
        return True
    spec = _BY_FN.get(fn_name)
    if spec is None:
        return True
    if not spec.needs:
        return True
    return bool(spec.needs & features)


def skipped(fn_names: Iterable[str], features: Set[str]) -> List[str]:
    return [n for n in fn_names if not should_run(n, features)]
