# crypto-helper
Crypto Helper for NodeJS

Support: TDES, DES  with mode ECB and CBC

Padding: PADDING_ZERO, PADDING_PKCS7



Public Methods:
```sh
tdes_enc_ecb(key, data) 

tdes_dec_ecb(key, data) 

tdes_enc_cbc(key, data, iv) 

tdes_dec_cbc(key, data, iv) 

des_enc_ecb(key, data) 

des_dec_ecb(key, data) 

padding(data, padding_type)

unpadding(data, padding_type)
```



# installation
```sh
$ nmp install @shenyan1206/crypto-helper --save
```

# example
```sh
var CryptoHelper = require("@shenyan1206/crypto-helper");

var key = Buffer.from("0123456789ABCDEFFEDCBA9876543210", "hex");
var data = Buffer.from("0102030405060708", "hex");

var ciphter_data = CryptoHelper.tdes_enc_ecb(key, data);

console.log(ciphter_data);
```
