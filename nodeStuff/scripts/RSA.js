var findPrime = require('find-prime');
var BigInteger = require('bigi');

var p;
var q;
var n;
var n_hex;
var totient;
var e;
var d;
var d_hex;
var m_hex;
var m;
var c;
var c_hex;
var c_string;
var m_prime;
var byteSize;
var cipherBuffer;
var ciphertext;

module.exports = {
	generateKeys : function(keySize)
	{
		findPrime(keySize / 2, function(error, prime) {
			p = prime;
		});

		do
		{
			findPrime(keySize / 2, function(error, prime) {
				q = prime;
			});
		} while(q.toString() == p.toString());

		n = p.multiply(q);

		totient = n.subtract(p.add(q.subtract(BigInteger.ONE)));

		do
		{
			// One less bit for e just to be sure we get a smaller value
			findPrime(keySize / 2, function(error, prime) {
				e = prime;
			});
		} while (e == p || e == q);

		d = e.modInverse(totient);
	},

	setByteSize : function(size)
	{
		byteSize = size;
	},

	getByteSize : function()
	{
		return byteSize;
	},

	setCipherBuffer : function(buffer)
	{
		cipherBuffer = buffer;
	},

	getCipherBuffer : function()
	{
		return cipherBuffer;
	},

	setCiphertext : function(cipher)
	{
		ciphertext = cipher;
	},

	getCiphertext : function()
	{
		return ciphertext;
	},

	encryptBuffer : function(buffer)
	{
		m = new BigInteger.fromBuffer(buffer);
		console.log(m.toString());
		c = m.modPow(e, n);
		return c;
	},

	encryptBigInteger : function(big)
	{
		m = big
		c = m.modPow(e, n);
		return c;
	},

	decryptBuffer : function(buffer)
	{
		c = new BigInteger.fromBuffer(buffer);
		m_prime = c.modPow(d, n);
		return m_prime;
	},

	decryptBufferPrevious : function()
	{
		m_prime = c.modPow(d, n);
		return m_prime;
	},

	encrypt : function(message)
	{
		m_hex = message;
		m = new BigInteger.fromHex(m_hex);
		c = m.modPow(e, n);
		return c;
	},

	decrypt : function()
	{
		m_prime = c.modPow(d, n);
		return m_prime.toHex();
	},

	decrypt_hex : function(n_in, d_in, c_in)
	{
		c = new BigInteger.fromHex(c_in);
		d = new BigInteger.fromHex(d_in);
		n = new BigInteger.fromHex(n_in);
		m_prime = c.modPow(d, n);
		return m_prime.toHex();
	},

	getPublicKey : function()
	{
		return {n : n.toString(), e : e.toString()};
	},

	getPublicKeyHex : function()
	{
		return {n : n.toHex(), e : e.toHex()};
	},

	getCipherHex : function()
	{
		return c.toHex();
	},


	getPrivateKey : function()
	{
		return d.toString();
	}, 
	getPrivateKeyHex : function()
	{
		return d.toHex();
	}
};

function getBaseLog(x, y) {
	return Math.log(y) / Math.log(x);
}