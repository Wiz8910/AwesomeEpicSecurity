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
	// generates a p and q which are large primes to create n
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

	// Sets a ciphertext to be used for decryption
	setCiphertext : function(cipher)
	{
		ciphertext = cipher;
	},

	// Gets the ciphertext used for decryption
	getCiphertext : function()
	{
		return ciphertext;
	},

	// Encrypt a big integer
	encryptBigInteger : function(big)
	{
		m = big
		c = m.modPow(e, n);
		return c;
	},

	// Decrypts an encrypted big integer
	decryptBigInteger : function(big)
	{
		c = big
		m_prime = c.modPow(d, n);
		return m_prime;
	},

	// Get hex representation of the public key
	getPublicKeyHex : function()
	{
		return {n : n.toHex(), e : e.toHex()};
	},

	// Get the hex representation of the private key
	getPrivateKeyHex : function()
	{
		return d.toHex();
	}
};