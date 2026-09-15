# EIP-7702 receiver-callback reentrancy — 동적 증명

`UniqueNFT7702.sol` 은 Pectra(EIP-7702) 이후 실제로 성립하는 취약 패턴이다:
mint 이전에 수신자 콜백을 호출하고 무료 경로를 `tx.origin == msg.sender` 로만 막으며
재진입 가드가 없다. 코드를 위임받은 EOA 가 그 게이트를 통과하면서 콜백으로 재진입해
`balanceOf==0` 유일성 검사를 우회, 한 주소에 2개 이상 민팅한다.

```bash
python3 agent/audit.py examples/eip7702/UniqueNFT7702.sol --out audit
#   → PROVEN · strategy=eip7702-reentrancy · balanceOf → 2
```

엔진은 이걸 **정적 휴리스틱이 아니라 동적으로 증명**한다:
1. 공격 EOA 가 악성 Delegate(콜백에서 재진입)에 EIP-7702 authorization 서명,
2. py-evm **prague** 포크에서 **type-4(SetCode) 트랜잭션**으로 `mintNFTEOA()` 호출,
3. `balanceOf(EOA) > 1` 을 실제 관찰 → PROVEN.

외부 import(OpenZeppelin 등) 때문에 샌드박스에서 컴파일되지 않는 원본은 같은 패턴을
`static_findings` 가 **HIGH 휴리스틱**으로 보고한다(오탐 0). CEI 를 지켜 상태 변경 뒤
콜백하면(안전본) 증명되지 않는다.
