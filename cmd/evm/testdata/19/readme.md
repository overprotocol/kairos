## Difficulty calculation

This test shows how the `evm t8n` can be used to calculate the (ethash) difficulty, if none is provided by the caller, 
this time on `GrayGlacier` (Eip 5133).

Calculating it (with an empty set of txs) using `GrayGlacier` rules (and no provided unclehash for the parent block):
```
[user@work evm]$ ./evm t8n --input.alloc=./testdata/19/alloc.json --input.txs=./testdata/19/txs.json --input.env=./testdata/19/env.json --output.result=stdout --state.fork=GrayGlacier
INFO [03-09|10:45:26.777] Trie dumping started                     root=6f0588..7f4bdc
INFO [03-09|10:45:26.777] Trie dumping complete                    accounts=2 elapsed="176.471µs"
INFO [03-09|10:45:26.777] Wrote file                               file=alloc.json
{
  "result": {
    "stateRoot": "0x38070dc11f96697a16f6420485f9362cc2ba3489b7ad5878ac4a05b2fa826398",
    "txRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    "logsHash": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
    "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "receipts": [],
    "currentDifficulty": "0x2000000004000",
    "gasUsed": "0x0",
    "currentBaseFee": "0x500"
  }
}
```