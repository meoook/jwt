# JWT Coder/Decoder 

* Version: 0.01.1
* Description: Validate or create JWT keys (HS256 only)
* Author: [meok][author]
* Depends: no (native)


- [x] Encode payload to JWT
- [x] Decode JWT to payload

# Example

```python
from jwt import JwtCoder

secret = 'your-256-bit-secret'
payload = {"ts": 3616239022}
jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0cyI6MzYxNjIzOTAyMn0.TcdSxFO_3XLb1mZu9urUhl5SVERC3ezEfxHVB9uvbnU'

coder = JwtCoder(secret, ts_name='ts')

print('OLD', jwt)
new_jwt = coder.encode(payload)
print('NEW', new_jwt)

payload_as_dict = coder.decode(jwt)
print('Validated', payload_as_dict)

empty_dict = coder.decode(jwt + 'any')
print('Not valid', empty_dict)
```

# Release notes

| version | date     | changes                                                            |
| ------- | -------- | ------------------------------------------------------------------ |
| 0.00.01 | 03.03.21 | Release                                                            |

[author]: <https://bazha.ru> "meok home page"
