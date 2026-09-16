# examples/families

트랙 12가 아니다. 엔진이 capability로 발화하는 **계열별 취약 컨트랙트**.
각 파일은 한 계열이다. 이름 하드코딩 없음 — `extract_features` 가 태그를 달고
`should_run(provider)` 가 합성을 연다.

```
python3 -m unittest tests.python.test_family_examples
```

| 파일 | 계열 | 출처 모양 |
|---|---|---|
| `UnpermissionedCallback.sol` | `unpermissioned_callback` | Truster / AtomicQueue |
| `DonationDoS.sol` | `donation_accounting_dos` | Unstoppable |
| `GovernanceFlash.sol` | `governance_flashloan` | Selfie |
| `ExecuteBeforeSchedule.sol` | `execute_before_schedule` | Climber |
| `TwapAsSpot.sol` | `twap_as_spot` | Puppet v1 (가짜 TWAP) |
| `WindowedTwap.sol` | `twap_window` | Uni V3 Observation[] |
| `CrossGetter.sol` | `cross_getter_drain` | 형제 게터 + 생성자 주소 |
| `VictimApprove.sol` | `victim_approve` | 피해자 approve 선행 |
| `SeededAllowance.sol` | `seeded_allowance_drain` | Setup이 남긴 allowance |
| `CrossChainBridge.sol` | `cross_chain_bridge` | lzReceive / relayMessage |
| `StructCtor.sol` | `struct_ctor` | `constructor(Init memory)` |
| `LiquidateOther.sol` | `liquidate_other` | Handsel MiniVault — 키 없는 청산 |
| `ImportedProtocol.sol` | `imported_protocol` | 다른 파일의 Uni/Aave |
| `OpaqueYul.sol` | `opaque_ir` | 순수 Yul (전문 synth 생략) |
| `ReadOnlyReentrancy.sol` | `readonly_reentrancy` | Curve 뷰가 잔액을 읽는 동안 콜백 |
| `VaultInflation.sol` | `vault_inflation` | ERC4626 첫 입금 인플레 |
| `HookReentrancy.sol` | `hook_reentrancy` | ERC777 훅 재진입 |
| `SigReplay.sol` | `sig_replay` | nonce 없는 ecrecover |
| `Metamorphic.sol` | `metamorphic` | CREATE2 + selfdestruct |
| `CommitReveal.sol` | `commit_reveal` | 커밋 후 다음 블록 리빌 |
| `ExternalErc.sol` | `external_erc` | 소스 없는 ERC-20/4626/Uni 셀렉터 |
| `MakeAddrVictim.sol` | `make_addr_victim` | forge-std makeAddr 키 파생 |
| `OffsetOwner.sol` | `owner_not_slot0` | owner 슬롯 1, 패딩 후 delegatecall |
| `MixedEntropy.sol` | `mixed_entropy` | keccak(blockhash, nonce) |

트랙 공개셋 대응은 `targets/` 에 있다 (재진입·tx.origin·오라클·delegatecall·난수·initializer).
의도 경로 카운터예제는 `examples/frontier/`.
카탈로그: [`catalog.json`](./catalog.json).
