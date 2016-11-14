var express = require('express');
var bodyParser = require('body-parser');
var ejs = require('ejs');
var path = require('path');
var app = express();
var rsa = require(path.join(__dirname, 'scripts', 'RSA.js'));
var fs = require('fs');

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
	res.send('done');
});

app.post('/encrypt_rsa', function (req, res) {
	var input = req.body;
	var keySize = input.Size;
	var message = input.Message;
	var file = input.File;
	var method = input.Input;

	var startTime;
	var endTime;

	var cipher;
	rsa.generateKeys(keySize);
	if(method == 'message')
	{
		startTime = new Date().getTime() / 1000;
		cipher = rsa.encrypt(toHex(message));
		endTime = new Date().getTime() / 1000;

		res.render(path.join(__dirname, 'views', 'RSAEncryptionResults.html'), 
			{ 	RSAMessage : message,
				RSAMessageHex : toHex(message),
				RSACipher : cipher.toHex(), 
				RSAPublicKey : rsa.getPublicKeyHex(),
				RSAPrivateKey : rsa.getPrivateKeyHex(),
				RSATime : (endTime - startTime)
			}
		);
	} 
	else
	{
		var fileInput = fs.readFile(path.join(__dirname, 'inputs', file), 'utf-8', function (err, data) {
			if(err)
			{
				throw (err);
			}
			startTime = new Date().getTime() / 1000;
			cipher = rsa.encrypt(toHex(data));
			endTime = new Date().getTime() / 1000;

			res.render(path.join(__dirname, 'views', 'RSAEncryptionResults.html'), 
				{ 	RSAMessage : message,
					RSAMessageHex : toHex(message),
					RSACipher : cipher.toHex(), 
					RSAPublicKey : rsa.getPublicKeyHex(),
					RSAPrivateKey : rsa.getPrivateKeyHex(),
					RSATime : (endTime - startTime)
				}
			);
		});
	}
});

app.post('/decrypt_rsa', function (req, res) {
	var input = req.body;
	var publicN = input.PublicN;
	var private = input.Private;
	var cipher = input.Cipher;
	var decrypt = input.Decrypt;
	var file = input.File;

	var message;
	var startTime;
	var endTime;

	console.log(decrypt);
	if(decrypt == 'previous')
	{
		startTime = new Date().getTime() / 1000;
		message = toString(rsa.decrypt());
		endTime = new Date().getTime() / 1000;

		res.render(path.join(__dirname, 'views', 'RSADecryptionResults.html'), 
		{ 	RSACipher : rsa.getCipherHex(),
			RSAMessage : message,
			RSATime : (endTime - startTime)});
	}
	else
	{
		if(decrypt == 'string')
		{
			startTime = new Date().getTime() / 1000;
			message = toString(rsa.decrypt_hex(publicN, private, cipher));
			endTime = new Date().getTime() / 1000;

			res.render(path.join(__dirname, 'views', 'RSADecryptionResults.html'), 
				{ 	RSACipher : rsa.getCipherHex(),
					RSAMessage : message,
					RSATime : (endTime - startTime)});
		}
		else if(decrypt == 'file')
		{
			var fileInput = fs.readFile(path.join(__dirname, 'inputs', file), 'utf-8', function (err, data) {
				if(err)
				{
					throw (err);
				}
				startTime = new Date().getTime() / 1000;
				message = toString(rsa.decrypt_hex(publicN, private, data));
				endTime = new Date().getTime() / 1000;

				var endTime = new Date().getTime() / 1000;

				res.render(path.join(__dirname, 'views', 'RSADecryptionResults.html'), 
					{ 	RSACipher : rsa.getCipherHex(),
						RSAMessage : message,
						RSATime : (endTime - startTime)});
			});
		}
	}
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