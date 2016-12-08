var express = require('express');
var bodyParser = require('body-parser');
var ejs = require('ejs');
var path = require('path');
var app = express();
var rsa = require(path.join(__dirname, 'scripts', 'RSA.js'));
var aes = require(path.join(__dirname, 'scripts', 'AES.js'));
var fs = require('fs');
var BigInteger = require('bigi');
var findPrime = require('find-prime');

// Using ejs to render html files 
app.engine('html', ejs.renderFile);

// Pass info from html to node
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Show the homepage 
app.get('/', function (req, res) {
	res.render(path.join(__dirname, 'views', 'index.html'));
});

app.post('/encrypt_aes', function (req, res) {
	var input = req.body;
	var keySize = input.Size;
	var file = input.File;
    var password = input.Pass;
    var initVector = input.InitVector;
    var newFile = input.NewFile;
    var method = input.Method;
	var startTime;
	var endTime;

	var cipher;
    //delete file if it exist
    fs.exists(path.join(__dirname, 'inputs', newFile),function(exists){
        if(exists){
            fs.unlink(path.join(__dirname, 'inputs', newFile));
        }
    });
    var fileInput = fs.readFile(path.join(__dirname, 'inputs', file), 'binary', function (err, data) {
        if(err)
        {
            throw (err);
        }
        startTime = new Date().getTime() / 1000;
        var wstream = fs.createWriteStream(path.join(__dirname, 'inputs', newFile),{flags:'a',encoding:'binary'});
        wstream.on('open',function(junk){
            var result = aes.encryptCipher(data,password,initVector,keySize,wstream,method);
            password = result[0];
            initVector = result[1];
            wstream.end();
            //now doing asyncrhonous writes
            //wstream.on('finish',function(){
            endTime = new Date().getTime() / 1000;
            res.render(path.join(__dirname, 'views', 'AESEncryptionResults.html'), 
                { 	
                    AESInput : data,
                    AESPassword: password,
                    AESCipher : cipher, 
                    AESKeyLength : keySize,
                    AESInitVector : initVector,
                    AESEncryptionTime : (endTime - startTime)
                }
            );
        });
        
    });
});
app.post('/decrypt_aes', function (req, res) {
	var input = req.body;
	var keySize = input.Size;
	var file = input.File;
    var password = input.Pass;
    var initVector = input.InitVector;
    var newFile = input.NewFile;
    var method = input.Method;
	var startTime;
	var endTime;
    
    //delete file if it exist
    fs.exists(path.join(__dirname, 'inputs', newFile),function(exists){
        if(exists){
            fs.unlink(path.join(__dirname, 'inputs', newFile));
        }
    });

	//aes.generateKeys(keySize);
    var fileInput = fs.readFile(path.join(__dirname, 'inputs', file), 'binary', function (err, data) {
        if(err)
        {
            throw (err);
        }
        
        startTime = new Date().getTime() / 1000;  
        var wstream = fs.createWriteStream(path.join(__dirname, 'inputs', newFile),{flags:'a',encoding:'binary'});
        wstream.on('open',function(test){
            aes.decryptCipher(data,password,initVector,keySize,wstream,method);
            wstream.end();//pointless to make user wait for write to finish, so gonna just spawn asyncrhonous writes
            //wstream.on('finish',function(){
            endTime = new Date().getTime() / 1000;
            res.render(path.join(__dirname, 'views', 'AESDecryptionResults.html'), 
                { 	
                    AESInput : data,
                    AESPassword: password,
                    AESKeyLength : keySize,
                    AESInitVector : initVector,
                    AESDecryptionTime : (endTime - startTime)
                }
            );
        });
    });
});

app.post('/encrypt_rsa', function (req, res) {
	// Get info on how to encrypt the file and which file to encrypt
	var input = req.body;
	var size = input.Size;
	var file = input.File;
	var newFile = input.NewFile;

	// Start and end time for tracking encryption
	var startTime;
	var endTime;

	// Read the input file
	fs.readFile(path.join(__dirname, 'inputs', file), function (err, fileInput) {
		// split File into 128 byte chunks which relates to a 1024 bit key size (can't go any smaller)
		var startSource = 0;
		var endSource = 128;
		var remainingBytes = fileInput.byteLength;
		var message = [];
		var index = 0;

		// Read the file into an array of buffers
		while(remainingBytes > 0)
		{
			if(remainingBytes >= 128)
				message[index] = new Buffer(128);
			else
				message[index] = new Buffer(remainingBytes);
			fileInput.copy(message[index], 0, startSource, endSource);
			startSource += 128;
			endSource += 128;
			index += 1;
			remainingBytes -= 128;
		}

		console.log('converting message to big integer');

		// Convert Message to BigIntegers
		var bigMessage = [];
		for(var i = 0; i < message.length; i++)
		{
			bigMessage[i] = new BigInteger.fromBuffer(message[i]);
		}
		
		console.log('generating keys');

		// Generate the RSA encryption keys
		var startTime = new Date().getTime() / 1000;
		rsa.generateKeys(size);

		console.log('encrypt message');

		// Encrypt each chunk
		var ciphertext = [];
		for(var i = 0; i < message.length; i++)
		{
			ciphertext[i] = rsa.encryptBigInteger(bigMessage[i]);
		}
		var endTime = new Date().getTime() / 1000;

		rsa.setCiphertext(ciphertext);
		
		// Create a buffer to write to a file
		var lastBuffer = new Buffer(ciphertext[ciphertext.length - 1].toBuffer(), 'base64');
		var bufferSize = ((ciphertext.length - 1) * 128 + lastBuffer.byteLength);
		var bigBuffer = new Buffer(bufferSize);
		for(var i = 0; i < ciphertext.length; i++)
		{
			var currentBuffer;
			if(i == ciphertext.length - 1)
				currentBuffer = lastBuffer;
			else
				currentBuffer = new Buffer(ciphertext[i].toBuffer(), 'base64');
			currentBuffer.copy(bigBuffer, i * 128, 0, currentBuffer.byteLength);
		}

		// write to file
		if(newFile != '')
		{
			console.log('printing to file');
			fs.writeFile(path.join(__dirname, 'inputs', newFile), bigBuffer, function(err) {});
		}

		// tell the world
		res.render(path.join(__dirname, 'views', 'RSAEncryptionResults.html'), 
			{ 	RSAMessage : message,
				RSACipher : new BigInteger.fromBuffer(bigBuffer).toString(), 
				RSAPublicKey : rsa.getPublicKeyHex(),
				RSAPrivateKey : rsa.getPrivateKeyHex(),
				RSATime : (endTime - startTime)
			}
		);

	});
});

app.post('/decrypt_rsa', function (req, res) {
	// Get where to store the decrypted file
	var input = req.body;
	var newFile = input.NewFile;

	// Start and end time for decryption
	var startTime;
	var endTime;

	console.log('getting cipher');

	// Get the ciphertext from the previous RSA encryption
	var ciphertext = rsa.getCiphertext();

	console.log('decrypt cipher');
	
	// Decrypt it
	startTime = new Date().getTime() / 1000;
	var plaintext = [];
	for(var i = 0; i < ciphertext.length; i++)
	{
		//var cipherBuffer = ciphertext[i].toBuffer();
		plaintext[i] = rsa.decryptBigInteger(ciphertext[i]);
	}
	endTime = new Date().getTime() / 1000;

	// Create a buffer to write to a file
	var lastBuffer = new Buffer(plaintext[plaintext.length - 1].toBuffer(), 'base64');
	var bufferSize = ((plaintext.length - 1) * 128 + lastBuffer.byteLength);
	var bigBuffer = new Buffer(bufferSize);
	for(var i = 0; i < plaintext.length; i++)
	{
		var currentBuffer;
		if(i == plaintext.length - 1)
			currentBuffer = lastBuffer;
		else
			currentBuffer = new Buffer(plaintext[i].toBuffer(), 'base64');
		currentBuffer.copy(bigBuffer, i * 128, 0, currentBuffer.byteLength);
	}

	// Write to file
	if(newFile != '')
	{
		console.log('printing to file');
		fs.writeFile(path.join(__dirname, 'inputs', newFile), bigBuffer, function(err) {});
	}

	// Tell the world how long it took
	res.render(path.join(__dirname, 'views', 'RSADecryptionResults.html'), 
	{ 	RSATime : (endTime - startTime)});
		
});

function toHex(str) {
	var hex = '';
	for(var i=0;i<str.length;i++) {
		hex += ''+str.charCodeAt(i).toString(16);
	}
	return hex;
}

function toString(hex) {
    var hex = hex.toString();//force conversion
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}

app.listen('3003');