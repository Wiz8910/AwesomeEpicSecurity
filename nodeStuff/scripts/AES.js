/**
 * 
 */
 
var charSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
 
module.exports ={
 
 /*
function test(e){
  var file = e.target.files[0];
  if (!file) {
    return;
  }
  var reader = new FileReader();
  reader.onload = function(e) {
    var contents = e.target.result;
    console.log("test");
    console.log(contents);
    var result =decrypt(encrypt(contents,document.getElementById('password').value,document.getElementById('keyLength').value),document.getElementById('password').value,document.getElementById('keyLength').value);
    console.log(result);
    if(result===contents){
        console.log("worked");
    }else{
        console.log("Bad Result");
    }
  };
  reader.readAsDataURL(file);
  document.getElementById('fileInput').value=null;
}
document.getElementById('fileInput').addEventListener('change', test, false);
*/

//inputFile is binary input to char[] as is password, keyLength is 128,192, or 256
    encrypt : function(inputFile, password, keyLength){
        //block size assumed to be constant for execution
        var blockSize = 16;
        if(keyLength!=128 && keyLength!=192 && keyLength!=256){
            document.getElementById('keyLength').value = "Enter 128 192 or 256";
            return;
        }
        //encrypt password to get cipher key
        var numBytes = keyLength/8;
        var passBytes = new Array(numBytes);
        
        //we take input password and if there are not enough characters add random characters
        for(var i=0; i<numBytes; i++){
            if(i>=password.length){
                var temp = charSet[Math.floor(Math.random()*charSet.length)];
                //document.getElementById('password').value = document.getElementById('password').value+temp;
                password= password+temp;
                passBytes[i] = password.charCodeAt(i);;
            }else{
                passBytes[i] = password.charCodeAt(i);
            }
        }
        //get the key based on password and keyExpansion function
        var key = Cipher(passBytes, keyExpansion(passBytes));
        
        //now initialize counterblock for count method
        var counterBlock = new Array(blockSize);
        
        var nonce = (new Date()).getTime();
        var nonceMS = nonce%1000;
        var nonceSec = Math.floor(nonce/1000);
        var nonceRnd = Math.floor(Math.random() * 0xffff);
        //counter is byte array length of 16
        //first 8 bytes set by the nonce, second eight bytes set by count
        for(var i=0; i<2; i++){counterBlock[i] = (nonceMS>>> i*8) & 0xff;}
        for(var i=0; i<2; i++){counterBlock[i+2] = (nonceRnd >>> i*8) & 0xff;}
        for(var i=0; i<4; i++){counterBlock[i+4] = (nonceSec >>> i*8) & 0xff;}
        //and convert it to a string to go on front of the ciphertext
        var counterText = '';
        for(var i=0;i<8;i++) { counterText+= String.fromCharCode(counterBlock[i]);}
        //generate key schedule - an expansion of the key into distinct Key Round for each round
        var keySchedule = keyExpansion(key);
        
        var blockCount = Math.ceil(inputFile.length/blockSize);
        var cipherText = '';
        
         for (var i=0; i<blockCount; i++) {
            //need to get rid of leading bits in int counter, this method of int to counter hex came from stackoverflow
            //we set the first half of counter with int converted to hex second half is nonce set to hex
            for (var k=0; k<4; k++) counterBlock[15-k] = (i >>> k*8) & 0xff;
            //then next 4 bits
            for (var k=0; k<4; k++) counterBlock[15-k-4] = (i/0x100000000 >>> k*8) & 0xff;

            var cipherCntr = Cipher(counterBlock, keySchedule);  //encrypt counter

            // block size is reduced on final block
            var blockLength = i<blockCount-1 ? blockSize : (inputFile.length-1)%blockSize+1;
            var cipherChar = new Array(blockLength);

            for (var k=0; k<blockLength; k++) {
                // xor inputFile with ciphered counter char
                cipherChar[k] = cipherCntr[k] ^ inputFile.charCodeAt(i*blockSize+k);
                cipherChar[k] = String.fromCharCode(cipherChar[k]);
            }
            cipherText += cipherChar.join('');
        }

        cipherText =  counterText+cipherText;
        return [cipherText,password];
    },

    decrypt : function(cipherText, password, keyLength) {
        var blockSize = 16;  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
        
        if(keyLength!=128 && keyLength!=192 && keyLength!=256){
            console.log("Bad keyLength "+keyLength);
            return;
        }
        // use AES to encrypt password (mirroring encrypt routine)
        var numBytes = keyLength/8;  // no bytes in key
        var passBytes = new Array(numBytes);
        for (var i=0; i<numBytes; i++) {
            //passBytes[i] = i<password.length ?  password.charCodeAt(i) : 0;
            if(i>=password.length){
                console.log("Error invalid password Length");
                return;
            }else{
                passBytes[i] = password.charCodeAt(i);
            }
        }
        var key = Cipher(passBytes, keyExpansion(passBytes));
        //key = key.concat(key.slice(0, numBytes-16));  // expand key to 16/24/32 bytes long

        // recover nonce from 1st 8 bytes of ciphertext
        var counterBlock = new Array(8);
        var counterText = cipherText.slice(0, 8);
        for (var i=0; i<8; i++){ counterBlock[i] = counterText.charCodeAt(i);}

        // generate key schedule
        var keySchedule = keyExpansion(key);

        // separate cipherText into blocks skipping past initial nonce
        var numBlocks = Math.ceil((cipherText.length-8) / blockSize);
        var count = new Array(numBlocks);
        for (var i=0; i<numBlocks; i++){ count[i] = cipherText.slice(8+i*blockSize, 8+i*blockSize+blockSize);}
        cipherText = count;  // cipherText is now array of block-length strings

        // plaintext will get generated block-by-block into array of block-length strings
        var plaintext = '';

        for (var i=0; i<numBlocks; i++) {
            // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
            for (var k=0; k<4; k++) counterBlock[15-k] = ((i) >>> k*8) & 0xff;
            for (var k=0; k<4; k++) counterBlock[15-k-4] = (((i+1)/0x100000000-1) >>> k*8) & 0xff;

            var cipherCntr = Cipher(counterBlock, keySchedule);  // encrypt counter block

            var plaintxtByte = new Array(cipherText[i].length);
            for (var k=0; k<cipherText[i].length; k++) {
                // -- xor plaintext with ciphered counter byte-by-byte --
                plaintxtByte[k] = cipherCntr[k] ^ cipherText[i].charCodeAt(k);
                plaintxtByte[k] = String.fromCharCode(plaintxtByte[k]);
            }
            plaintext += plaintxtByte.join('');
        }
        return plaintext;
    },
}
// Round Constant used for the Key Expansion
var RCon = [ [ 0x00, 0x00, 0x00, 0x00 ],
             [ 0x01, 0x00, 0x00, 0x00 ],
             [ 0x02, 0x00, 0x00, 0x00 ],
             [ 0x04, 0x00, 0x00, 0x00 ],
             [ 0x08, 0x00, 0x00, 0x00 ],
             [ 0x10, 0x00, 0x00, 0x00 ],
             [ 0x20, 0x00, 0x00, 0x00 ],
             [ 0x40, 0x00, 0x00, 0x00 ],
             [ 0x80, 0x00, 0x00, 0x00 ],
             [ 0x1b, 0x00, 0x00, 0x00 ],
             [ 0x36, 0x00, 0x00, 0x00 ] ];
             
// given box of multiplicative inverses
var sBox = [ 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
             0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
             0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
             0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
             0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
             0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
             0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
             0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
             0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
             0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
             0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
             0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
             0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
             0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
             0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
             0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 ];
             
//input is bits to convert, word - key schedule 2d byte-array(128,192,256 bits)
var Cipher = function(input, word){
    var blockSize = 4;
    var  rounds = word.length/blockSize - 1;
    var state = [[], [], [], []];
    //need to convert input to 2d byte array
    for (var i=0; i<4*blockSize; i++) state[i%4][Math.floor(i/4)] = input[i];
    state = AddRoundKey(state,word,0,blockSize);
    //last round is different behavior
    for(var i=1; i<rounds-1; i++){
        state = SubBytes(state,blockSize);
        state = ShiftRows(state,blockSize);
        state = MixColumns(state,blockSize);
        state = AddRoundKey(state,word,i,blockSize);
    }
    //final round slightly different, no MixColumns
    state = SubBytes(state,blockSize);
    state = ShiftRows(state,blockSize);
    state = AddRoundKey(state,word,rounds-1,blockSize);
    
    //now output as 1d array
    var output = new Array(4*blockSize);
    for (var i=0; i<4*blockSize; i++) output[i] = state[i%4][Math.floor(i/4)];
    return output;
}

//function to generate key Schedule
var keyExpansion = function(key){
    var blockSize = 4;
    var keyLength;
    if(key.length == 16){
        keyLength = 4;
    }else if(key.length == 24){
        keyLength = 6;
    }else{
        keyLength = 8;
    }
    var rounds = keyLength + 6;
    
    var keySchedule = new Array(blockSize*(rounds+1));
    var temp = new Array(blockSize);
    
    //initialize first keyLength words of expanded key with cipher
    for(var i=0; i<keyLength;i++){
        var tempArray = [key[4*i],key[4*i+1],key[4*i+2],key[4*i+3]];
        keySchedule[i] = tempArray;
    }
    //now expand the key
    for(var i=keyLength; i<(blockSize*(rounds+1));i++){
        keySchedule[i] = new Array(blockSize);
        for(var k=0; k<blockSize;k++){  temp[k] = keySchedule[i-1][k];}
        if(i%keyLength==0){
            temp = SubWord(RotWord(temp));
            for(var k=0; k<4; k++) { temp[k] ^= RCon[i/keyLength][k];}
        }else if(keyLength==8 && i%keyLength==4){
            temp = SubWord(temp);
        }
        //now xor
        for(var k=0; k<blockSize;k++){keySchedule[i][k] = keySchedule[i-keyLength][k] ^ temp[k];}
    }
    return keySchedule;

}

//AddRoundKey from psuedocode
var AddRoundKey = function(state,word, round, blockSize){
    for(var i=0; i<4; i++){
        for(var k=0; k<blockSize; k++){
            state[i][k] ^= word[round*4+k][i];
        }
    }
    return state;
}

//use the given sBox on state
var SubBytes = function(state){
    for(var i=0; i<4; i++){
        for(var k=0; k<4;k++){
            state[i][k] = sBox[state[i][k]];
        }
    }
    return state;
}

//use Substitute box for keyShift
var SubWord = function(word){
    for(var i=0; i<4; i++){
        word[i] = sBox[word[i]];
    }
    return word;
}

//rotation for keyShift
var RotWord = function(word){
    var tmp = word[0];
    for(var i=0; i<3; i++){ word[i] = word[i+1]; }
    word[3] = tmp;
    return word;
}

//shift row of state left
var ShiftRows = function(state){
    var temp = new Array(4);
    for(var i=1; i<4; i++){
      for(var k=0; k<4; k++){ temp[k] = state[i][(i+k)%4];}
      for(var k=0; k<4; k++){ state[i][k] = temp[k];}
    }
    return state;
}

//combine bytes of columns
var MixColumns = function(state,blockSize){
    for(var i=0; i<4; i++){
        var column1 = new Array(4);
        var column2 = new Array(4);
        for(var k=0;k<4;k++){
            column1[k] = state[k][i];
            //do division
            column2 = state[k][i]&0x80? state[k][i]<<1 ^ 0x011b : state[k][i]<<1;
        }
        //operations I don't really understand, just doing what I was told
        state[0][i] = column2[0] ^column1[1]^column2[1]^column1[2]^column1[3];
        state[1][i] = column1[0] ^column2[1]^column1[1]^column2[2]^column1[3];
        state[2][i] = column1[0] ^column1[1]^column2[1]^column1[2]^column2[3];
        state[3][i] = column1[0] ^column2[1]^column1[1]^column1[2]^column2[3];
    }
    return state;
}