# Pairing incarnation candidate: byte-level vectors

Status: **UNAPPROVED. Test inputs only.** These vectors are for independent
review of `INCARNATION_PROTOCOL_CANDIDATE.md` revision 3. They are not a
protocol implementation, not a security proof, and not evidence about any TLS
stack, device, or storage API. No network, route, TUN device, emulator, or device
was used. No Python was used.

The tags below were computed with SHA-256 and HMAC arithmetic through `openssl`
in a POSIX shell, then checked a second time through the `openssl mac` command.
The exporter value `E` is a fixed test input. A matching tag proves only that the
arithmetic in this file is internally consistent. It does not prove that any TLS
stack returns `E` or that Rust, Swift, and Android agree on an exporter.

## 0. Tag input correction

Revision 2 of the protocol said the tagged `frame` starts at `version` and
excludes the 4-byte length prefix. Its vectors were computed with the length
prefix included twice: once in the separate `u32be(frame_len)` and once inside
`frame`. Both cannot be true.

Revision 3 keeps the written definition. The tag input is:

```
"HotspotShade-v2-frame\0" || channel_u8 || direction_u8 ||
u32be(frame_len) || frame_from_version_to_last_suffix_byte
```

Therefore every tag in this file differs from revision 2, and every frame of a
type whose layout changed differs as well. A test that copies a revision 2 tag
will fail, by design.

The `frame` value printed in each section includes the 4-byte length prefix.
`wire = frame || tag`. Each frame section in section 3 has exactly one
`frame = ` line and one `tag   = ` line so a harness can walk this file in
order.

## 1. Fixed inputs

All values are hex. A repeated byte is written once in the name and expanded in
the value.

| Name | Value |
|---|---|
| `source_pin` | `1111111111111111111111111111111111111111111111111111111111111111` |
| `target_pin` | `2222222222222222222222222222222222222222222222222222222222222222` |
| `I` | `3333333333333333333333333333333333333333333333333333333333333333` |
| `P` | `4444444444444444444444444444444444444444444444444444444444444444` |
| `begin_nonce` | `55555555555555555555555555555555` |
| `target_arm_id` | `66666666666666666666666666666666` |
| `offer_nonce` | `77777777777777777777777777777777` |
| `source_arm_id` | `88888888888888888888888888888888` |
| `bootstrap_hash` | `9999999999999999999999999999999999999999999999999999999999999999` |
| `operation_id` | `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` |
| `query_id` | `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb` |
| `session_nonce` | `cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc` |
| `target_instance_nonce` | `dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd` |
| `source_instance_nonce` | `eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee` |
| `source_epoch` | `0000000000000001` |
| `target_epoch` | `0000000000000001` |
| `state_seq` | `00000001` where a record has one transition, `00000000` where it has none |
| `session_seq` | `0000000000000001` |
| `target_stop_seq` | `0000000000000000` |

The two instance nonces are independent in this file. Revision 2 used one value
for both, which hid a swapped-field defect. A parser must use the declared field
order and must reject a frame with the two swapped.

The state sequence values are fixed test inputs. They are not derived from a
full ceremony history. A real record must produce them by the rules in the
protocol. These vectors use 0 for a record with no transition, 1 for one
transition, and 2 for two. A real record's value follows from its own durable
history, which may include a consent write or an earlier transition.

## 2. Frame key

```
E    = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
salt = 486f7473706f7453686164652d76322d73616c7400
PRK  = 449b600cb7c11ffd9c212b4bf81e943f184bf79f45ba9581ecda02ea5fed0bb4
info = 486f7473706f7453686164652d76322d6672616d652d6b65790001
K    = 9fd47ba554277f73d9266e6cfed2cd2895f8c2201e9dbe3618dc9026897ec519
```

`salt` is `"HotspotShade-v2-salt\0"` in ASCII. `info` is
`"HotspotShade-v2-frame-key\0" || 0x01`. `PRK` is
`HMAC-SHA256(salt, E)`. `K` is `HMAC-SHA256(PRK, info)`.

The tag label is `"HotspotShade-v2-frame\0"`:

```
486f7473706f7453686164652d76322d6672616d6500
```

`channel = 01` for pairing, `02` for proxy. `direction = 01` for S to T, `02`
for T to S.

## 3. Frames

Each entry gives the exact frame without the tag, then the tag. `frame` includes
the 4-byte length prefix. `wire = frame || tag`. Lengths are total bytes and
include the tag.

### 3.1 BEGIN, T to S

`frame_len = 176` (`000000b0`), suffix 44, total 212. `I = 0`.

Fields after `P`: `begin_nonce`, `target_arm_id`, `target_epoch = 1`, `mode = 1`,
`flags = 0`, `reserved = 0`.

```
frame = 000000b0020b000011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000000044444444444444444444444444444444444444444444444444444444444444445555555555555555555555555555555566666666666666666666666666666666000000000000000101000000
tag   = 7708553a4a5ea1fe4fdc1240ac08c4ce3a161239bc261d076d360ba7040834f8
```

### 3.2 OFFER, S to T, first send

`frame_len = 216` (`000000d8`), suffix 84, total 252. `source_epoch = 1`,
`target_epoch = 1`, `mode = 1`, `flags = 0`, `reserved = 0`.

```
frame = 000000d8020100001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444555555555555555555555555555555556666666666666666666666666666666677777777777777777777777777777777888888888888888888888888888888880000000000000001000000000000000101000000
tag   = e443591e3c5c73c0c6becf6081d67702efa1f713be42be78258fe632c67c136e
```

### 3.3 OFFER, S to T, duplicate

Same frame as 3.2 except `flags = 1` (`DUPLICATE`). This is the exact duplicate
BEGIN response. The reservation and the epochs do not change.

```
frame = 000000d8020100001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444555555555555555555555555555555556666666666666666666666666666666677777777777777777777777777777777888888888888888888888888888888880000000000000001000000000000000101010000
tag   = 089ebe9d3cd7b07d9527c86b1921ff3d95e110c533321b1868fd902afe2802f7
```

An OFFER with `flags = 2` (`STATE_DERIVED`) is a protocol error. OFFER writes no
receipt, so it can never carry that flag.

### 3.4 PAIR_DONE, T to S

`frame_len = 248` (`000000f8`), suffix 116, total 284. `bootstrap_hash =
9999...99` is a placeholder for a real hash. A real implementation must reject it
unless it equals `SHA-256(B)`.

```
frame = 000000f80202000011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333344444444444444444444444444444444444444444444444444444444444444445555555555555555555555555555555566666666666666666666666666666666777777777777777777777777777777778888888888888888888888888888888800000000000000010000000000000001999999999999999999999999999999999999999999999999999999999999999901000000
tag   = 7b9eed6b48f75bc12a0099f56cde06343921a5160a78b6e3be52abb931e43ced
```

### 3.5 PAIR_RESULT, S to T, first commit

`frame_len = 200` (`000000c8`), suffix 68, total 236. `result = 1` COMMITTED,
`tuple_state = 2` ACTIVE, `flags = 0`, `state_seq = 1`,
`current_source_epoch = 1`. The trailing `current_source_epoch` is new in
revision 3.

```
frame = 000000c80203000011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333344444444444444444444444444444444444444444444444444444444444444440102000000000000000000010000000000000001000000010000000099999999999999999999999999999999999999999999999999999999999999990000000000000001
tag   = 2f5c41e9ddfb78aa6f604baf19e01d755507b609ec5f5525ca21f18aceffe443
```

### 3.6 PAIR_RESULT, S to T, duplicate

Same record and state, `flags = 1` (`DUPLICATE`). `current_source_epoch` is the
newest retained source epoch for the pair at response time, which is still 1.

```
frame = 000000c80203000011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333344444444444444444444444444444444444444444444444444444444444444440102010000000000000000010000000000000001000000010000000099999999999999999999999999999999999999999999999999999999999999990000000000000001
tag   = 70985de984e1ec893a38d95b259f94fa8f08eda554f704ae32bb1d33670d95c5
```

### 3.7 PAIR_RESULT, S to T, state-derived ABORTED

`result = 2` ABORTED, `tuple_state = 3` TERMINAL, `flags = 2`
(`STATE_DERIVED`), `state_seq = 2`. The record was promoted once and then
terminalized once. A state-derived result never writes a receipt. The hash is
the stored hash of the terminal record, or zero when the record was terminalized
before any hash. Here it is nonzero.

```
frame = 000000c80203000011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333344444444444444444444444444444444444444444444444444444444444444440203020000000000000000010000000000000001000000020000000099999999999999999999999999999999999999999999999999999999999999990000000000000001
tag   = 62ccdbfdc27125e136f306815876db4cdbf299351d5f187c3bc7c450fe34ddef
```

A state-derived `COMMITTED` for this record with this `I` and `P` but a
different hash is `CONFLICT`, not `COMMITTED`. See N39.

### 3.8 CANCEL, T to S, exact

`frame_len = 216` (`000000d8`), suffix 84, total 252. `intent = 1` EXACT,
`flags = 0`, `begin_nonce`, `target_arm_id`, expected epochs 1. The nonce and arm
fields are new in revision 3; without them the source had no lookup key that
matched the protocol text.

```
frame = 000000d8020400001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01000000555555555555555555555555555555556666666666666666666666666666666600000000000000010000000000000001
tag   = b8635b1f970d57877fba95bf75674ec5bc6c972a4387b5e5b78a3b03f0c22e13
```

### 3.9 CANCEL, T to S, pre-offer

`I = 0`, same suffix width, `intent = 2` PRE_OFFER, `expected_source_epoch = 0`,
`expected_target_epoch = 1`, with the target's `begin_nonce` and
`target_arm_id`.

```
frame = 000000d8020400001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000000000000000004444444444444444444444444444444444444444444444444444444444444444aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02000000555555555555555555555555555555556666666666666666666666666666666600000000000000000000000000000001
tag   = b365608f0c68f4ea1c0bce2bfaedc77ef71fac1550f9cdeee0e58239ceb5e8f3
```

### 3.10 FORGET, T to S

Same layout as CANCEL with `type = 5`, `intent = 1`, nonzero `I`.

```
frame = 000000d8020500001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01000000555555555555555555555555555555556666666666666666666666666666666600000000000000010000000000000001
tag   = 2662626a3b5519afa6e932eab998ac7d75a2f41ce1341be92d2f108f1a6ef30b
```

### 3.11 REMOVE_RESULT, S to T, FORGET removed

`frame_len = 200` (`000000c8`), suffix 68, total 236. `request_type = 5`,
`result = 1` REMOVED, `tuple_state = 3` TERMINAL, `flags = 0`. A PENDING record
was terminalized, so `state_seq = 1` and `current_source_epoch = 1`.

```
frame = 000000c802060000111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444444444444444444444444444405010300aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000001000000000000000100000001000000000000000000000001
tag   = 6a0b1d369ab6c5b34efe980d9b6d19f82bfafed0bc03d0b2e4d9aa0761b3fe44
```

### 3.12 REMOVE_RESULT, S to T, pre-offer tombstone

This is the frame revision 2 could not encode. A pre-offer CANCEL reached a
source with no record. The source wrote a tombstone.

`request_type = 4`, `result = 1` REMOVED, `tuple_state = 5` TOMBSTONE, `flags =
0`, `I = 0`, `operation_id` from the request, `source_epoch = 0`,
`target_epoch = 1` from the tombstone, `state_seq = 0`, `current_source_epoch =
0` because no source record exists for the pair.

```
frame = 000000c802060000111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220000000000000000000000000000000000000000000000000000000000000000444444444444444444444444444444444444444444444444444444444444444404010500aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000000000000100000000000000000000000000000000
tag   = 7ff0415528015d2a63e3c44dce776b6e5ebd1c82623b92fdda34552bfe8b2da3
```

### 3.13 REMOVE_RESULT, S to T, pre-offer cancel that terminalized PENDING

`request_type = 4`, `result = 1` REMOVED, `tuple_state = 3` TERMINAL, `flags =
0`. The request carried `I = 0`, but the response reports the found record's
`I`, epochs, and `state_seq`. A response to a zero-I request may therefore carry
a nonzero `I` when a record was actually removed. The two pre-offer outcomes are
distinguishable by `tuple_state`.

```
frame = 000000c802060000111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444444444444444444444444444404010300aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000001000000000000000100000001000000000000000000000001
tag   = bee6425b6c1cc02465294a5583d06b284cc6dae87176f7a750ba00d2fc704656
```

### 3.14 QUERY, T to S

`frame_len = 164` (`000000a4`), suffix 32, total 200. `I` is nonzero.

```
frame = 000000a4020700001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
tag   = e0bd73c5e9545ba9f2e17eeb1eb7dd6c5ba8565e64fcb060af0716c986b7f53b
```

### 3.15 QUERY_RESULT, S to T, ACTIVE

`frame_len = 232` (`000000e8`), suffix 100, total 268. `state = 2` ACTIVE,
`flags = 0`, nonzero hash, `state_seq = 1`, `current_source_epoch = 1`.

```
frame = 000000e8020800001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0200000000000000000000010000000000000001000000010000000099999999999999999999999999999999999999999999999999999999999999990000000000000001
tag   = d35c766866656b61aff6b1d189fec24ee4eeb1977430d43eb282593a894ee4fb
```

### 3.16 QUERY_RESULT, S to T, PENDING with a zero hash

`state = 1` PENDING, `flags = 0`, `bootstrap_hash` all zero, `state_seq = 0`
because the record has had no transition, `current_source_epoch = 1`. Revision 2
showed a nonzero placeholder hash here, which contradicted the rule that a
PENDING record reports zero until PAIR_DONE supplies a verified hash.

```
frame = 000000e8020800001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100000000000000000000010000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
tag   = 3c6bc40edbda42472d65a836ef4c9417582facbeb8fb3f0337f9beb90eb31524
```

Zero is not a hash match. A target with a nonzero local hash must not accept this
result as confirmation.

### 3.17 SESSION_OPEN, T to S, proxy channel

`frame_len = 224` (`000000e0`), suffix 92, total 260. `known = 1`, `flags = 0`,
stop sequence 0. `channel = 02`, `direction = 02`.

```
frame = 000000e0020900001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc00000000000000010000000000000001dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd000000000000000001000000
tag   = 56689c363b77bd332ad159286395e9bd1fb80607934a71ee79b082c1f7170f8a
```

### 3.18 SESSION_RESULT, S to T, ACCEPTED, proxy channel

`frame_len = 232` (`000000e8`), suffix 100, total 268. `result = 1` ACCEPTED,
`flags = 0`, `session_seq = 1`, `source_instance_nonce` independent of the target
instance nonce. `channel = 02`, `direction = 01`.

```
frame = 000000e8020a00001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000000000000000000100000000000000010000000100000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000001
tag   = 8158a590d4630bdeb8a93d4ccbf74532593c38023070019186d179747f042ca4
```

### 3.19 SESSION_RESULT, S to T, BUSY, proxy channel

`result = 4` BUSY, `session_seq = 0` because no session was registered. This is
the answer to a retry of a live SESSION_OPEN with the same nonce.

```
frame = 000000e8020a00001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc04000000000000000000000100000000000000010000000100000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000
tag   = 7e0601b3cc8d1c42da023decd7c6506c7734430e1cfb56970429ee5998180e6e
```

### 3.20 LOOKUP, T to S

`frame_len = 196` (`000000c4`), suffix 64, total 232. `I = 0`, exact
`begin_nonce` and `target_arm_id`.

```
frame = 000000c4020c00001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000000000000000004444444444444444444444444444444444444444444444444444444444444444bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb5555555555555555555555555555555566666666666666666666666666666666
tag   = 98b252618c75b6b48455c3f8afab51bc4f79e6fe5d60062c6a8b825250b100a1
```

### 3.21 LOOKUP_RESULT, S to T, PENDING

`frame_len = 296` (`00000128`), suffix 164, total 332. `state = 1` PENDING,
`flags = 0`, `I` is the found record's `I`, `bootstrap_hash` all zero,
`state_seq = 0`, `current_source_epoch = 1`.

```
frame = 00000128020d00001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb010000000000000000000001000000000000000100000000000000005555555555555555555555555555555566666666666666666666666666666666777777777777777777777777777777778888888888888888888888888888888800000000000000000000000000000000000000000000000000000000000000000000000000000001
tag   = 0590b2f8c4f29d60252ee83374c42a5462b58007ff90d3b3c3e23d4ffda14ee7
```

### 3.22 LOOKUP_RESULT, S to T, TOMBSTONE

`state = 5` TOMBSTONE, `flags = 0`, `I = 0`, `source_epoch = 0`,
`target_epoch = 1` from the tombstone, `state_seq = 0`. `begin_nonce` and
`target_arm_id` are the tombstone's. `offer_nonce` and `source_arm_id` are zero
because no record exists. `bootstrap_hash` is zero. `current_source_epoch = 0`.

```
frame = 00000128020d00001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000000000000000004444444444444444444444444444444444444444444444444444444444444444bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb050000000000000000000000000000000000000100000000000000005555555555555555555555555555555566666666666666666666666666666666000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
tag   = df5a742cf8f8d04dbb4e6ca3b8b01ab000f4e825de87ebde7f3cffe633934153
```

### 3.23 REFUSED, S to T, BEGIN NO_ARM

`frame_len = 200` (`000000c8`), suffix 68, total 236. `request_type = 11`,
`code = 2` NO_ARM, `tuple_state = 4` UNKNOWN, `flags = 0`, `I = 0` because the
request was BEGIN, `operation_id = P`, zero epochs, zero `state_seq`, zero
`current_source_epoch`. Revision 2's vector carried a nonzero `I` here, which its
own rule did not allow.

```
frame = 000000c8020e000011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000000044444444444444444444444444444444444444444444444444444444444444440b02040044444444444444444444444444444444444444444444444444444444444444440000000000000000000000000000000000000000000000000000000000000000
tag   = 5fa7c95056c8506171366cdf776621c0d3aecc6187af47e496eed88e4c0bbdf4
```

### 3.24 REFUSED, S to T, PAIR_DONE CONFLICT

`request_type = 2`, `code = 5` CONFLICT, `tuple_state = 4` UNKNOWN, `flags = 0`,
`I` is the request's `I`, `operation_id = P`, zero epochs because no record
exists, `current_source_epoch = 0`.

```
frame = 000000c8020e000011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333344444444444444444444444444444444444444444444444444444444444444440205040044444444444444444444444444444444444444444444444444444444444444440000000000000000000000000000000000000000000000000000000000000000
tag   = 1aa2ac81fee3703bc6e30781845b77cedaa93e09f5d41204f038bc2bb784617b
```

## 4. Bootstrap transcript and hashes

### 4.1 SAS

```
B =
  486f7473706f7453686164652d76322d626f6f74737472617000
  1111111111111111111111111111111111111111111111111111111111111111
  2222222222222222222222222222222222222222222222222222222222222222
  3333333333333333333333333333333333333333333333333333333333333333
  4444444444444444444444444444444444444444444444444444444444444444
  0000000000000001
  0000000000000001
  88888888888888888888888888888888
  66666666666666666666666666666666
  55555555555555555555555555555555
  77777777777777777777777777777777
  01
  00000000
```

The full byte string is:

```
486f7473706f7453686164652d76322d626f6f74737472617000111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444444444444444444444444444400000000000000010000000000000001888888888888888888888888888888886666666666666666666666666666666655555555555555555555555555555555777777777777777777777777777777770100000000
```

Length 239 bytes. `bootstrap_hash = SHA-256(B) =`
`1a837fb3df79ae839ad914b7d7075eeff3dd78f44209699e7784584de680a0c4`.

`SHA-256("HotspotShade-v2-sas\0" || bootstrap_hash) =`
`186fa86bbd214be255877e3a28fa180a591161bf5741728c33ac1cf307b36f6f`.

The first 20 bits are `0x186fa` = 100090. The six-digit code is `100090`.

### 4.2 QR

The QR payload is 212 bytes:

```
0202000011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333344444444444444444444444444444444444444444444444444444444444444440000000000000001000000000000000188888888888888888888888888888888666666666666666666666666666666665555555555555555555555555555555577777777777777777777777777777777
```

`B` is the same 239-byte prefix with `mode = 02` and `len =
000000d4`, followed by those 212 bytes. `B` is 451 bytes. Its hash is
`a5eae4a96e7f88c179d4f49761d3d6e9517c4de7dd4a8aaa7802462ca714e095`.

The full `B` for QR is:

```
486f7473706f7453686164652d76322d626f6f747374726170001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444000000000000000100000000000000018888888888888888888888888888888866666666666666666666666666666666555555555555555555555555555555557777777777777777777777777777777702000000d40202000011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333344444444444444444444444444444444444444444444444444444444444444440000000000000001000000000000000188888888888888888888888888888888666666666666666666666666666666665555555555555555555555555555555577777777777777777777777777777777
```

The payload is single use and is not a text rendering. A scanner must return
these exact bytes.

## 5. Operation key and fingerprint vectors

For a CANCEL or FORGET with the fixed pins, `I`, `P`, and operation ID above, the
operation key is type-independent:

```
request_key = 626eaa3b8054dd155f72ec9f439e932e64ef0f3c2baa99eb38f155f2920cd841
```

A CANCEL and a FORGET that reuse the same `operation_id` have the same key and
different fingerprints. That is `CONFLICT` by the receipt rule. It is not two
independent operations.

For the CANCEL exact frame in section 3.8, without the tag:

```
request_fp = 2502833de6af32f4fdb4b1aa15a075d67644e40363b2f2b9f7251cb37ee496c9
```

For the CANCEL pre-offer frame in section 3.9:

```
request_fp = 60a0be3408d215b68d2ac5e79b10fefbd84eff5bca526cc8fae2e55d3935fb81
```

For the FORGET frame in section 3.10:

```
request_fp = fb305113f6d2d3c9c19bff7c7f60355953ac092da3d9e2962095afc27d6e8064
```

A duplicate must match both the key and the fingerprint. A same-key,
different-fingerprint request is `CONFLICT` and must not overwrite the receipt.

## 6. Negative vectors

There are two kinds of negative row. The order matters.

A **tag-first** row changes a byte of the frame and keeps the old tag. The tag
covers every byte, so the tag fails before any field is read. These rows test the
"tag before parse" rule.

A **field-after-tag** row changes a field and presents a correctly recomputed
tag. These rows test the field and state rules. A harness that cannot recompute a
tag cannot run them.

Every negative row has one expected outcome: a fixed rejection before any state
change, no response frame, and the connection closed. A row that produces a
result frame is a defect.

### 6.1 Tag-first rows

| # | Input | Expected |
|---|---|---|
| N1 | BEGIN with `frame_len = 000000b1` and the section 3.1 tag | Reject at tag verification. No parse, no state change |
| N2 | BEGIN with one trailing byte after the tag | Reject at length or tag |
| N3 | BEGIN with a truncated tag | Reject truncation |
| N4 | PAIR_DONE with `source_pin` changed by one byte and the old tag | Reject at tag. No record |
| N5 | SESSION_OPEN on channel `01` with the channel `02` tag | Reject tag |
| N6 | SESSION_OPEN with direction `01` and the direction `02` tag | Reject tag |
| N7 | PAIR_RESULT with direction `02` and the direction `01` tag | Reject tag |
| N8 | PAIR_RESULT with channel `02` and the channel `01` tag | Reject tag |
| N9 | Any frame replayed on a second TLS connection | Reject tag, because `K` differs |

### 6.2 Field-after-tag rows

Each row recomputes the tag over the changed frame before sending.

| # | Input | Expected |
|---|---|---|
| N10 | BEGIN with `version = 3` | Reject version |
| N11 | PAIR_DONE with `type = 15` | Reject unknown type |
| N12 | OFFER with `reserved = 1` | Reject reserved |
| N13 | PAIR_DONE with `mode = 3` | Reject enum |
| N14 | BEGIN with `flags = 8` (bit 3 set) | Reject undefined flag bit |
| N15 | OFFER with `flags = 2` (`STATE_DERIVED`) | Reject. OFFER may carry only bit 0 |
| N16 | BEGIN with `flags = 1` (`DUPLICATE`) | Reject. BEGIN carries no flags |
| N17 | PAIR_RESULT with `flags = 3` (`DUPLICATE` and `STATE_DERIVED`) | Reject. The two bits are exclusive |
| N18 | REFUSED with `state = 6` | Reject unknown state |
| N19 | CANCEL with `intent = 3` | Reject enum |
| N20 | FORGET with `intent = 2` | Reject. FORGET is exact only |
| N21 | CANCEL PRE_OFFER with nonzero `I` | Reject field rule |
| N22 | CANCEL EXACT with `I = 0` | Reject field rule |
| N23 | CANCEL PRE_OFFER with nonzero `expected_source_epoch` | Reject field rule |
| N24 | CANCEL EXACT with zero `begin_nonce` or zero `target_arm_id` | Reject zero field |
| N25 | PAIR_DONE with `target_epoch = 0` | Reject zero epoch |
| N26 | REFUSED with `request_type = 11` and nonzero `I` | Reject response `I` rule |
| N27 | REFUSED with `request_type = 2` and `I = 0` | Reject response `I` rule |
| N28 | REMOVE_RESULT with `request_type = 5` and `I = 0` | Reject response `I` rule |
| N29 | REMOVE_RESULT with `request_type = 4`, `tuple_state = 5`, nonzero `source_epoch` | Reject state-field rule |
| N30 | LOOKUP_RESULT with `state = 5` and nonzero `bootstrap_hash` | Reject state-field rule |
| N31 | LOOKUP_RESULT with `state = 4` and nonzero `state_seq` | Reject state-field rule |
| N32 | LOOKUP_RESULT with `state = 5` and nonzero `offer_nonce` | Reject state-field rule |
| N33 | QUERY with `I = 0` | Reject. QUERY names a record |
| N34 | PAIR_RESULT with `current_source_epoch = 0` while a record exists | Reject state-field rule |
| N35 | Two frames in one TLS record | Parse both in order. Do not merge |
| N36 | One frame split over two TLS records | Reassemble and deliver once |

### 6.3 State and transcript rows

These rows use valid frames and valid tags. They test state, not parsing.

| # | Input | Expected |
|---|---|---|
| N37 | PAIR_DONE with `bootstrap_hash = 9999...99` against the SAS record | `CONFLICT`. No promotion |
| N38 | PAIR_DONE with a hash for a different `P` | `CONFLICT`. No promotion |
| N39 | State-derived PAIR_DONE for an ACTIVE record with a wrong hash | `CONFLICT`, not `COMMITTED` |
| N40 | State-derived PAIR_DONE for an ACTIVE record with a wrong `offer_nonce` | `CONFLICT`, not `COMMITTED` |
| N41 | State-derived PAIR_DONE for a TERMINAL record with a matching tuple and a zero stored hash | `ABORTED` with `STATE_DERIVED`. No promotion |
| N42 | PAIR_RESULT with a hash that differs from the target's stored hash | No promotion. Report a conflict |
| N43 | PAIR_RESULT with `current_source_epoch` newer than the record's | No promotion. The record is superseded |
| N44 | A second pre-offer CANCEL for the same `P` with a new operation ID | `REMOVED`, `STATE_DERIVED`, no second tombstone |
| N45 | A pre-offer CANCEL with the same `P` and a different nonce | `CONFLICT`. No tombstone |
| N46 | BEGIN with the `begin_nonce` of a retained terminal record and a new `P` | `CONFLICT`. No reservation |
| N47 | SESSION_OPEN retry with the same nonce while the first session is live | `BUSY`, `session_seq = 0`, one session |
| N48 | SESSION_OPEN retry with the same nonce after the first connection closed | `ACCEPTED`, new `session_seq`, one session |
| N49 | SESSION_OPEN with a swapped instance nonce pair | The result is discarded by the target. No credential |
| N50 | FORGET repeated after a `DENIED` with the same operation ID | `DENIED` from the denial slot, not `REMOVED` |
| N51 | Pre-offer CANCEL whose `expected_target_epoch` differs from the record | `CONFLICT`. No mutation |
| N52 | Pre-offer CANCEL whose `expected_target_epoch` differs from the tombstone | `CONFLICT`. No mutation |

## 7. Field and length summary

| Type | `frame_len` | Total | Changed in revision 3 |
|---|---|---|---|
| BEGIN | 176 | 212 | No layout change, new tag |
| OFFER | 216 | 252 | No layout change, new tag |
| PAIR_DONE | 248 | 284 | No layout change, new tag |
| PAIR_RESULT | 200 | 236 | `current_source_epoch` added |
| CANCEL | 216 | 252 | `begin_nonce` and `target_arm_id` added |
| FORGET | 216 | 252 | `begin_nonce` and `target_arm_id` added |
| REMOVE_RESULT | 200 | 236 | No layout change, new tag |
| QUERY | 164 | 200 | No layout change, new tag |
| QUERY_RESULT | 232 | 268 | No layout change, new tag |
| SESSION_OPEN | 224 | 260 | No layout change, new tag |
| SESSION_RESULT | 232 | 268 | No layout change, new tag |
| LOOKUP | 196 | 232 | No layout change, new tag |
| LOOKUP_RESULT | 296 | 332 | No layout change, new tag |
| REFUSED | 200 | 236 | No layout change, new tag |

The smallest total is 200 bytes (QUERY). The largest is 332 bytes
(LOOKUP_RESULT). A parser may reject any total outside those bounds before it
looks at the type.

## 8. What these vectors do not prove

- They do not prove TLS exporter equality or availability on any stack.
- They do not prove that a bootstrap display is authentic or that a person
  confirmed it.
- They do not prove durable storage, atomic replacement, locking, rollback
  detection, or crash recovery.
- They do not prove that a source device is the intended physical device.
- They do not prove that a tombstone capacity rule behaves as specified at a
  real capacity boundary. N44 and N45 test identity, not the cap.
- They do not prove that v2 can interoperate with v1.
- They do not authorize implementation or a device test.
