var crypto = require("crypto");


//constructor
function CryptoHelper(){
	this.PADDING_ZERO = 0;
	this.PADDING_PKCS7 = 7;

};

//private functions
function encrypt(algorithm, key, data, iv)
{
	var cipher = crypto.createCipheriv(algorithm, key, iv);
	cipher.setAutoPadding(false);
	var crypted = Buffer.concat([cipher.update(data), cipher.final()]);
	return crypted;

}

function decrypt(algorithm, key, data, iv)
{
	var decipher = crypto.createDecipheriv(algorithm, key, iv);
  	decipher.setAutoPadding(false);
  	var clear_data = Buffer.concat([decipher.update(data), decipher.final()]);
  	return clear_data;
}


//class functions

//key: Buffer
//data: Buffer, auto padding with 0x00 if not multiple of 8 bytes

//TDES
CryptoHelper.prototype.tdes_enc_ecb = function(key, data) 
{
	if(key.length == 16) key = Buffer.concat([key,  key.slice(0, 8)]); //append first block to form 3 keys: [k1, k2, k1]
	if(data.length % 8 > 0) data = this.Padding(data, this.PADDING_ZERO);
	return encrypt("des-ede3", key, data, Buffer.alloc(0));
}

CryptoHelper.prototype.tdes_dec_ecb = function(key, data) 
{
	if(key.length == 16) key = Buffer.concat([key,  key.slice(0, 8)]); //append first block to form 3 keys: [k1, k2, k1]
	return decrypt("des-ede3", key, data, Buffer.alloc(0));
}

CryptoHelper.prototype.tdes_enc_cbc = function(key, data, iv) 
{
	if(key.length == 16) key = Buffer.concat([key,  key.slice(0, 8)]); //append first block to form 3 keys: [k1, k2, k1]
	if(data.length % 8 > 0) data = this.Padding(data, this.PADDING_ZERO);
	return encrypt("des-ede3-cbc", key, data, iv);}

CryptoHelper.prototype.tdes_dec_cbc = function(key, data, iv) 
{
	if(key.length == 16) key = Buffer.concat([key,  key.slice(0, 8)]); //append first block to form 3 keys: [k1, k2, k1]
	return decrypt("des-ede3-cbc", key, data, iv);
}


//DES
CryptoHelper.prototype.des_enc_ecb = function(key, data) 
{
	return encrypt("des-ecb", key, data, Buffer.alloc(0));
}
CryptoHelper.prototype.des_dec_ecb = function(key, data) 
{
	return decrypt("des-ecb", key, data, Buffer.alloc(0));
}




//PADDING
CryptoHelper.prototype.padding = function(data, padding_type)
{
	//if(data.length % 8 == 0) return data; //no need to pad

	var padding_len = 8 - data.length % 8;
	var result = Buffer.alloc(data.length + padding_len);

	if(padding_type == this.PADDING_ZERO) result.fill(0);
	if(padding_type == this.PADDING_PKCS7) result.fill(padding_len);

	data.copy(result, 0, 0); //(target[, targetStart[, sourceStart[, sourceEnd]]])

	return result;
}


CryptoHelper.prototype.unpadding = function(data, padding_type)
{
	var result_length = data.length;
	if(padding_type == this.PADDING_ZERO)
	{
		while( result_length>0 && data[result_length-1] == 0) result_length--; //check last char
	}
	if(padding_type == this.PADDING_PKCS7)
	{
		result_length = data.length - data[data.length-1];
	}

	return Buffer.from(data.slice(0, result_length));
}




CryptoHelper.prototype.kcv = function(key)
{
	return this.tdes_enc_ecb(key, Buffer.alloc(8).fill(0)).slice(0,3); //encrypt one block of zero, take first 6 hex (3 bytes)
}

CryptoHelper.prototype.generateKeyOfSize = function(size)
{
	return crypto.randomBytes(size);
}



/* ************************************************************************
SINGLETON CLASS DEFINITION
************************************************************************ */
CryptoHelper.instance = null;
/**
 * Singleton getInstance definition
 * @return singleton class
 */
CryptoHelper.getInstance = function(){
    if(this.instance === null){
        this.instance = new CryptoHelper();
    }
    return this.instance;
}
 
module.exports = CryptoHelper.getInstance();

