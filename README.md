# Padding Oracle Attack Implementation

## Overview

**Cipher Block Chaining Mode**로 암호화된 시스템에서 발생할 수 있는 취약점인 **Padding Oracle Attack**을 Python으로 구현한 결과물입니다.

공격자는 Encryption Key를 모르는 상태에서도, 서버(Oracle)가 반환하는 **Padding Validity** 여부만을 이용하여 암호화된 메시지를 평문으로 복호화할 수 있습니다.

## Key Technologies & Environment

- **Language**: Python
- **Networking**: Socket Programming
- **Cryptography**:
- Block Cipher 구조 이해
- CBC Mode of Operation
- PKCS#7 Padding Standard
- **Tools**: Custom Oracle Server (Python provided interfaces)

## 3. Technical Logic

### 3.1. Theoretical Background

CBC 모드에서 복호화 과정은 다음과 같습니다.

#### Definition
- $P_{i}$: 평문 Block
- $C_{i}$: 현재 암호문 블록
- $C_{i-1}$은 이전 암호문 블록 (첫 블록의 경우 **Initialization Vector**)

공격자는 $C_{i-1}$의 특정 바이트를 조작하여 오라클에 전송합니다. 오라클이 패딩이 올바르다고 응답할 때까지 바이트를 변경(0x00 ~ 0xFF)하며 시도(Brute-force)합니다. 이를 통해 **Intermediate State(중간 상태)** 값을 알아내고, 최종적으로 평문을 복구합니다.

### 3.2. Implementation Details (구현 상세)

* **Socket Communication**: `oracle_python_v1_2.py`를 통해 로컬에 구동된 오라클 서버와 소켓 통신을 수행하며 패딩의 유효성을 검증합니다.
* **Byte-level Manipulation**: `padding oracle attack.py`에서 `hex_to_bytes`, `bytes_to_hex` 등의 함수를 통해 16진수 문자열과 바이트 배열 간의 변환을 처리합니다.
* **Backward Iteration**: 블록의 마지막 바이트부터 첫 번째 바이트까지 역순으로 값을 추측하며, 이미 알아낸 값을 이용해 다음 바이트를 계산하는 알고리즘을 구현했습니다.
* **False Positive Handling**: 우연히 패딩이 맞는 경우(예: 패딩이 `0x02 0x02`가 되어야 하는데 `0x01`로 인식되는 등)를 방지하기 위해, 이전 바이트를 추가로 조작하여 검증하는 로직을 포함하여 정확도를 높였습니다.

```python
# 코드 주요 로직 예시 (False Positive 검증)
if ret == 1: # 패딩이 유효하다고 응답받은 경우
    if k == BLOCK_SIZE - 1:
        # 마지막 바이트의 경우 우연한 매칭을 방지하기 위해 
        # 이전 바이트를 조작하여 재검증 수행
        test_C0_bytes[k-1] ^= 0xFF
        # ... (재검증 로직)

```

## 4. How to Run (실행 방법)

1. **오라클 서버 실행**: 제공된 Java 혹은 Python 기반의 오라클 서버를 실행하여 포트를 오픈합니다.
2. **포트 설정**: `port` 파일에 실행된 서버의 포트 번호를 저장합니다.
3. **공격 스크립트 실행**:
```bash
python "padding oracle attack.py" <C0_Hex_String> <C1_Hex_String>

```


* `C0_Hex_String`: 이전 암호문 블록 (또는 IV)
* `C1_Hex_String`: 복호화하고자 하는 타겟 암호문 블록



## 5. Learning Outcomes (배운 점)

* **Side-Channel Attack(부채널 공격)**의 위험성: 암호 알고리즘 자체가 강력하더라도, 구현상의 사소한 정보 유출(에러 메시지 등)이 치명적인 보안 허점을 만들 수 있음을 깨달았습니다.
* **Protocol Compliance(프로토콜 준수)**: 암호화 프로토콜 구현 시, 복호화 실패에 대한 응답 처리가 보안에 미치는 영향을 이해했습니다.
* **Data Structure Manipulation(자료구조 조작)**: 파이썬을 이용하여 바이트 단위의 데이터를 정밀하게 제어하고 네트워크로 전송하는 실무적인 코딩 능력을 향상했습니다.

---

### 제안하는 다음 단계 (Next Step)

작성된 코드를 보면 `False Positive`를 처리하는 부분이 인상적입니다. 이 내용은 면접관에게 어필하기 좋은 포인트입니다.

**이 내용으로 깃허브에 업로드하기 전에, 코드 내 주석을 영어로 번역하거나 좀 더 상세하게 다듬어 드리는 작업을 진행할까요?**
