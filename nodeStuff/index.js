var express = require('express');
var bodyParser = require('body-parser');
var ejs = require('ejs');
var path = require('path');
var app = express();
var rsa = require(path.join(__dirname, 'scripts', 'RSA.js'));
var aes = require(path.join(__dirname, 'scripts', 'AES.js'));
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
        wstream.on('open',function(res){
            var result = aes.encryptCipher(data,password,initVector,keySize,wstream,method);
            password = result[0];
            initVector = result[1];
            wstream.end();
        });
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
       // });
        
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
        wstream.on('open',function(res){
            aes.decryptCipher(data,password,initVector,keySize,wstream,method);
            wstream.end();
        });
        //pointless to make user wait for write to finish, so gonna just spawn asyncrhonous writes
        //wstream.on('finish',function(){
        endTime = new Date().getTime() / 1000;
        res.render(path.join(__dirname, 'views', 'AESDecryptionResults.html'), 
            { 	
                AESInput : data,
                AESPassword: password,
                //AESCipher : plaintext, 
                AESKeyLength : keySize,
                AESInitVector : initVector,
                AESDecryptionTime : (endTime - startTime)
            }
        );
        //});
    });
});

app.post('/encrypt_rsa', function (req, res) {
	var input = req.body;
	var keySize = input.Size;
	var message = input.Message;
	var file = input.File;
	var method = input.Input;
	var newFile = input.NewFile;

	var startTime;
	var endTime;

	var cipher;
	rsa.generateKeys(keySize);
	if(method == 'message')
	{
		startTime = new Date().getTime() / 1000;
		cipher = rsa.encrypt(toHex(message));
		endTime = new Date().getTime() / 1000;

		if(newFile!=""){
            fs.writeFile(path.join(__dirname, 'inputs', newFile), cipher.toHex(), 'binary', function (err) {
                if(err)
                {
                    throw (err);
                }
            });
        }

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
		var fileInput = fs.readFile(path.join(__dirname, 'inputs', file), 'binary', function (err, data) {
			if(err)
			{
				throw (err);
			}
			startTime = new Date().getTime() / 1000;
			cipher = rsa.encrypt(toHex(data));
			endTime = new Date().getTime() / 1000;

			if(newFile!=""){
            fs.writeFile(path.join(__dirname, 'inputs', newFile), cipher.toHex(), 'binary', function (err) {
	                if(err)
	                {
	                    throw (err);
	                }
	            });
	        }

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
	var newFile = input.NewFile;

	var message;
	var startTime;
	var endTime;

	if(decrypt == 'previous')
	{
		startTime = new Date().getTime() / 1000;
		message = toString(rsa.decrypt());
		endTime = new Date().getTime() / 1000;

		if(newFile!=""){
            fs.writeFile(path.join(__dirname, 'inputs', newFile), message.toHex(), 'binary', function (err) {
                if(err)
                {
                    throw (err);
                }
            });
        }

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

			if(newFile!=""){
	            fs.writeFile(path.join(__dirname, 'inputs', newFile), message, 'binary', function (err) {
	                if(err)
	                {
	                    throw (err);
	                }
	            });
	        }

			res.render(path.join(__dirname, 'views', 'RSADecryptionResults.html'), 
				{ 	RSACipher : rsa.getCipherHex(),
					RSAMessage : message,
					RSATime : (endTime - startTime)});
		}
		else if(decrypt == 'file')
		{
			var fileInput = fs.readFile(path.join(__dirname, 'inputs', file), 'binary', function (err, data) {
				if(err)
				{
					throw (err);
				}
				startTime = new Date().getTime() / 1000;
				message = toString(rsa.decrypt_hex(publicN, private, data));
				endTime = new Date().getTime() / 1000;

				if(newFile!=""){
		            fs.writeFile(path.join(__dirname, 'inputs', newFile), message, 'binary', function (err) {
		                if(err)
		                {
		                    throw (err);
		                }
		            });
		        }

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