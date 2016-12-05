/**
 * 
 */
 
var charSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
var maxBytes = 300000;

module.exports ={

    encryptCipher : function(inputFile, password, initVector,keyLength,fileWriter,mode){
        //block size assumed to be constant for execution
        var blockSize = 16;
        if(keyLength!=128 && keyLength!=192 && keyLength!=256){
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
        //add to init vector if need be
        var initBytes=new Array(numBytes);
        if(mode==="cbc"){
            for(var i=0; i<numBytes; i++){
                if(i>=initVector.length){
                    var temp = charSet[Math.floor(Math.random()*charSet.length)];
                    initVector= initVector+temp;
                    initBytes[i] = initVector.charCodeAt(i);;
                }else{
                    initBytes[i] = initVector.charCodeAt(i);
                }
            }
        }
        
        //console.log(passBytes);
        //get the key based on password and keyExpansion function
        var key = Cipher(passBytes, keyExpansion(passBytes));
        
        //now initialize counterblock for count method
        var plaintextBlock = new Array(blockSize);
        
        //get the key schedule
        var keySchedule = keyExpansion(key);
        
        var blockCount = Math.ceil(inputFile.length/blockSize);
        var padLength;
        if(inputFile.length%blockSize==0){
            padLength = blockSize;
            blockCount = blockCount+1;
        }else{
            padLength = inputFile.length%blockSize;
        }
        var cipherText = [];
        var prevCipherBlock;
        var outText="";
        for (var i=0; i<blockCount; i++) {
            // block size is reduced on final block
            //var blockLength = i<blockCount-1 ? blockSize : (inputFile.length-1)%blockSize+1;
            
            for(var k=0;k<blockSize;k++){
                if(i*blockSize+k>inputFile.length){
                    plaintextBlock[k] = padLength;
                }else{
                    plaintextBlock[k]=inputFile.charCodeAt(i*blockSize+k);
                }
            }
            if(mode==="cbc"){
                if(i==0){
                    //xor first block with password
                    for (var k=0; k<blockSize; k++) {
                        // xor inputFile with ciphered counter char
                        plaintextBlock[k] = initBytes[k] ^ plaintextBlock[k];
                        //plaintextBlock[k] = String.fromCharCode(plaintextBlock[k]);
                    }
                }else{
                    //
                    //otherwise xor with prevCipherBlock
                    for (var k=0; k<blockSize; k++) {
                        // xor inputFile with ciphered counter char
                        plaintextBlock[k] = prevCipherBlock[k] ^ plaintextBlock[k];
                    }
                }
            }
            var cipherBlock = Cipher(plaintextBlock, keySchedule);  //encrypt counter
            
            var formatted ="";
            for(var k=0;k<cipherBlock.length;k++){
                formatted+=String.fromCharCode(cipherBlock[k]);
            }
            outText+=formatted;
            if(i%maxBytes==0){
                fileWriter.write(outText,'binary');
                outText="";
            }
            if(mode==="cbc"){
                prevCipherBlock = cipherBlock;
            }
        }
        if(outText!=""){
            fileWriter.write(outText,'binary');
        }
        //console.log(prevCipherBlock);
        return [password,initVector];
    },

    decryptCipher: function(inputFile, password, initVector,keyLength,fileWriter,mode){
        
        var blockSize = 16;
        if(keyLength!=128 && keyLength!=192 && keyLength!=256){
            return;
        }
        
        //encrypt password to get cipher key
        var numBytes = keyLength/8;
        var passBytes = new Array(numBytes);
        //we take input password and if there are not enough characters error out
        for(var i=0; i<numBytes; i++){
            passBytes[i] = password.charCodeAt(i);
        }
        var initBytes = new Array(numBytes);
        if(mode==="cbc"){
            for(var i=0; i<numBytes; i++){
                initBytes[i] = initVector.charCodeAt(i);
            }
        }
        //get the key based on password and keyExpansion function
        var key = Cipher(passBytes, keyExpansion(passBytes));
        
        //now initialize counterblock for count method
        var encryptextBlock = new Array(blockSize);
        
        //get the key schedule
        var keySchedule = keyExpansion(key);
        
        var blockCount = Math.ceil(inputFile.length/blockSize);
        var cipherXor;
        var prevCipherBlock;
        var outText="";
        var bytesRemaining;
        for (var i=0; i<blockCount; i++) {
            // block size is reduced on final block
            for(var k=0;k<blockSize;k++){
                encryptextBlock[k]=inputFile.charCodeAt(i*blockSize+k);
            }
            //console.log(encryptextBlock);
            var plainBlock = decrCipher(encryptextBlock, keySchedule);  //encrypt counter
            if(mode ==="cbc"){
                if(i==0){
                    //xor first block with password
                    for (var k=0; k<blockSize; k++) {
                        // xor inputFile with ciphered counter char
                        plainBlock[k] = initBytes[k] ^ plainBlock[k];
                        //plainBlock[k] = String.fromCharCode(plainBlock[k]);
                    }
                    prevCipherBlock = encryptextBlock.slice();
                }else{
                    //otherwise xor with prevPlainBlock
                    for (var k=0; k<blockSize; k++) {
                        // xor inputFile with ciphered counter char
                        plainBlock[k] = prevCipherBlock[k] ^ plainBlock[k];
                        //plainBlock[k] = String.fromCharCode(plainBlock[k]);
                    }
                    prevCipherBlock = encryptextBlock.slice();
                }
            }
            var formatted ="";
            var bytesRemaining = inputFile.length -i*blockSize;
            for(var k=0;k<plainBlock.length;k++){
                //need to drop the padding from output
                if(!(plainBlock[k] == bytesRemaining && bytesRemaining<=blockSize)){
                    formatted+=String.fromCharCode(plainBlock[k]); 
                }
            }
            if(formatted!=""){
                outText+=formatted;
            }
            if(i%maxBytes==0){
                fileWriter.write(outText,'binary');
                outText="";
            }
        }
        if(outText!=""){
            fileWriter.write(outText,'binary');
        }
        return;
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
var InvsBox = [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
               0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
               0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
               0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
               0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
               0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
               0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
               0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
               0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
               0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
               0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
               0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
               0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
               0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
               0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
               0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
              ];
            
//input is bits to convert, word - key schedule 2d byte-array(128,192,256 bits)
var Cipher = function(input, word){
    var blockSize = 4;
    var  rounds = word.length/blockSize - 1;
    var state = [[], [], [], []];
    //need to convert input to 2d byte array
    for (var i=0; i<4*blockSize; i++) state[i%4][Math.floor(i/4)] = input[i];
    state = AddRoundKey(state,word,0,blockSize);
    //last round is different behavior
    for(var i=1; i<rounds; i++){
        state = SubBytes(state,blockSize);
        state = ShiftRows(state,blockSize);
        state = MixColumns(state,blockSize);
        state = AddRoundKey(state,word,i,blockSize);
    }
    //final round slightly different, no MixColumns
    state = SubBytes(state,blockSize);
    state = ShiftRows(state,blockSize);
    state = AddRoundKey(state,word,rounds,blockSize);
    
    //now output as 1d array
    var output = new Array(4*blockSize);
    for (var i=0; i<4*blockSize; i++) output[i] = state[i%4][Math.floor(i/4)];
    return output;
}

//input is bits to convert, word - key schedule 2d byte-array(128,192,256 bits)
var decrCipher = function(input, word){
    var blockSize = 4;
    var rounds = word.length/blockSize - 1;
    var state = [[], [], [], []];
    //need to convert input to 2d byte array
    for (var i=0; i<4*blockSize; i++) state[i%4][Math.floor(i/4)] = input[i];
    state = AddRoundKey(state,word,rounds,blockSize);
    
    for(var i=rounds-1; i>0; i--){
        state = InvShiftRows(state,blockSize);
        state = InvSubBytes(state,blockSize);
        state = AddRoundKey(state,word,i,blockSize);
        state = InvMixColumns(state,blockSize);
    }
    
    //first round slightly different, no MixColumns
    state = InvShiftRows(state,blockSize);
    state = InvSubBytes(state,blockSize);
    state = AddRoundKey(state,word,0,blockSize);
    
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
var AddRoundKey = function(state,word, round, blockSize,decrypting){
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

var InvSubBytes = function(state){
    for(var i=0; i<4; i++){
        for(var k=0; k<4;k++){
            state[i][k] = InvsBox[state[i][k]];
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

var InvShiftRows = function(state){
    var temp = new Array(4);
    for(var i=1; i<4; i++){
      for(var k=3; k>=0; k--){ temp[k] = state[i][(4-i+k)%4];}
      for(var k=3; k>=0; k--){ state[i][k] = temp[k];}
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
        }
        //do polynomial multiplication with given numbers
        state[0][i] = polyMult(column1[0],2)^polyMult(column1[1],3)^polyMult(column1[2],1)^polyMult(column1[3],1);
        state[1][i] = polyMult(column1[0],1)^polyMult(column1[1],2)^polyMult(column1[2],3)^polyMult(column1[3],1);
        state[2][i] = polyMult(column1[0],1)^polyMult(column1[1],1)^polyMult(column1[2],2)^polyMult(column1[3],3);
        state[3][i] = polyMult(column1[0],3)^polyMult(column1[1],1)^polyMult(column1[2],1)^polyMult(column1[3],2);
    }
    return state;
}

//polynomial multiplication for given field. Doing operations as outlined in docs
var polyMult = function(a,b){
    var result = 0;
    if(a==0||b==0){return result;}
    if(a==1){return b;}
    if(b==1){return a;}
    //console.log(a+" "+b);
    for (var i = 0; i < 8; i++) {
        if (b & 1) result ^= a;
        var hiBitSet = a & 0x80;
        a = (a << 1) & 0xFF;
        if (hiBitSet) a ^= 0x1b;
        b >>>= 1;
    }
    //console.log(result);
    return result&0xFF;
}

var InvMixColumns = function(state,blockSize){
    for(var i=0; i<4; i++){
        var column1 = new Array(4);
        for(var k=0;k<4;k++){
            column1[k] = state[k][i];
        }
        //do polynomial multiplication with given numbers
        state[0][i] = polyMult(column1[0],0x0E)^polyMult(column1[1],0x0B)^polyMult(column1[2],0x0D)^polyMult(column1[3],0x09);
        state[1][i] = polyMult(column1[0],0x09)^polyMult(column1[1],0x0E)^polyMult(column1[2],0x0B)^polyMult(column1[3],0x0D);
        state[2][i] = polyMult(column1[0],0x0D)^polyMult(column1[1],0x09)^polyMult(column1[2],0x0E)^polyMult(column1[3],0x0B);
        state[3][i] = polyMult(column1[0],0x0B)^polyMult(column1[1],0x0D)^polyMult(column1[2],0x09)^polyMult(column1[3],0x0E);
    }
    return state;
}