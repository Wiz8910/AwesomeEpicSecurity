// RCon is Round Constant used for the Key Expansion
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
    var  rounds = word.length/(blockSize - 1);
    var state = [[], [], [], []];
    //need to convert input to 2d byte array
    for(var i=0; i<4; i++){
        for(var k=0; k<4; k++){
            state[i][k] = input[i*4+k];
        }
    }
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
    state = AddRoundKey(state,word,rounds,blockSize);
    
    //now output as 1d array
    var output = new Array(4*blockSize);
    for(var i=0; i<4*blockSize;i++){
        for(var k=0; k<blockSize; k++){
            output[i*4+k] = state[i][k];
        }
    }
}

//function to generate key Schedule
var keyExpansion = function(key){
    var blockSize = 4;
    var keyLength;
    if(key.length === 128){
        keyLength = 4;
    }else if(key.length == 192){
        keyLength = 6;
    }else{
        keyLength = 8;
    }
    var rounds = keyLength + 6;
    
    var keySchedule = new Array(blockSize*(rounds+1));
    var temp = new Array(blockSize);
    
    //initialize first keyLength words of expanded key with cipher
    for(var i=0; i<keyLength;i++){
        keySchedule[i] = [key[4*i],key[4*i+1],key[4*i+2],key[4*i+3]];
    }
    //now expand the key
    for(var i=keyLength; i<(blockSize*(rounds+1));i++){
        keySchedule[i] = new Array(blockSize);
        for(var k=0; k<blockSize;k++){  temp[k] = keySchedule[i-1][k];}
        if(i%keyLength==0){
            temp = subWord(rotWord(temp));
            for(var k=0; k<4; k++) { temp[k] ^= RCon[i/keyLength][k];}
        }else if(keyLength>6 && i%keyLength==4){
            temp = subWord(temp);
        }
        //now xor
        for(var k=0; k<blockSize;k++){keySchedule[i][k] = keySchedule[i-keyLength][k] ^ temp[k];}
    }
    return keySchedule;

}


var AddRoundKey = function(state,word, round, blockSize){
    for(var i=0; i<4; i++){
        for(var k=0; k<blockSize; k++){
            state[i][k] ^= word[round*4+k][k];
        }
    }
    return state;
}

//use the given sBox on state
var SubBytes = function(state){
    for(var i=0; i<4; i++){
        for(var k=0; k<4;k++){
            state[i][k] = sBox[s[r][c]];
        }
    }
    return state;
}

//use Substitute box for keyShift
var SubWord = function(word){
    for(var i=0; i<4; i++){
        word[i] = sBox[w[i]];
    }
    return word;
}

//rotate for keyShift
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
            column2 = state[k][i]&0x80? state[k][i]<<1 ^ 0x011b : s[k][i]<<1;
        }
        //operations I don't really understand, just doing what I was told
        state[0][i] = column2[0] ^column1[1]^column2[1]^column1[2]^column1[3];
        state[1][i] = column1[0] ^column2[1]^column1[1]^column2[2]^column1[3];
        state[2][i] = column1[0] ^column1[1]^column2[1]^column1[2]^column2[3];
        state[3][i] = column1[0] ^column2[1]^column1[1]^column1[2]^column2[3];
    }
    return state;
}

//inputFile is utf8Encoded input, as is password keyLength is 128,192, or 256
var encrypt = function(inputFile, password, keyLength){
    var blockSize = keyLength/8;
    
    //TODO: make this mine
    //encrypt password to get cipher key
    var numBytes = keyLength/8;
    var passBytes = new Array(numBytes);
    for(var i=0; i<numBytes; i++){
        passBytes = i<password.length?password.charCodeAt(i):0;
    }
    var key = Cipher(passBytes, keyExpansion(passBytes));
    key = key.concat(key.slice(0, numBytes -16));
    
    var counterBlock = new Array(blockSize);
    
    var nonce = (new Date()).getTime();
    var nonceMS = nonce%1000;
    var nonceSec = Math.floor(nonce/1000);
    var nonceRnd = Math.floor(Math.random() * 0xffff);
    
    for(var i=0; i<2; i++){counterBlock[i] = (nonceMS>>> i*8) & 0xff;}
    for(var i=0; i<2; i++){counterBlock[i+2] = (nonceRnd >>> i*8) & 0xff;}
    for(var i=0; i<4; i++){counterBlock[i+4] = (nonceSec >>> i*8) & 0xff;}
    
    //and convert it to a string to go on front of the ciphertext
    var ctrTxt = '';
    for(var i=0;i<8;i++) { ctrTxt+= String.fromCharCode(counterBlock[i]);}
    
    //generate key schedule - an expansion of the key into distinct Key Round for each round
    var keySchedule = keyExpansion(key);
    
    var blockCount = Math.ceil(plaintext.length/blockSize);
    var cipherText = '';
    
      for (var b=0; b<blockCount; b++) {
        // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
        // done in two stages for 32-bit ops: using two words allows us to go past 2^32 blocks (68GB)
        for (var c=0; c<4; c++) counterBlock[15-c] = (b >>> c*8) & 0xff;
        for (var c=0; c<4; c++) counterBlock[15-c-4] = (b/0x100000000 >>> c*8);

        var cipherCntr = Cipher(counterBlock, keySchedule);  // -- encrypt counter block --

        // block size is reduced on final block
        var blockLength = b<blockCount-1 ? blockSize : (plaintext.length-1)%blockSize+1;
        var cipherChar = new Array(blockLength);

        for (var i=0; i<blockLength; i++) {
            // -- xor plaintext with ciphered counter char-by-char --
            cipherChar[i] = cipherCntr[i] ^ plaintext.charCodeAt(b*blockSize+i);
            cipherChar[i] = String.fromCharCode(cipherChar[i]);
        }
        ciphertext += cipherChar.join('');

        // if within web worker, announce progress every 1000 blocks (roughly every 50ms)
        if (typeof WorkerGlobalScope != 'undefined' && self instanceof WorkerGlobalScope) {
            if (b%1000 == 0) self.postMessage({ progress: b/blockCount });
        }
    }

    ciphertext =  (ctrTxt+ciphertext).base64Encode();

    return ciphertext;
    
}

/**
 * Decrypt a text encrypted by AES in counter mode of operation
 *
 * @param   {string} ciphertext - Cipher text to be decrypted.
 * @param   {string} password - Password to use to generate a key for decryption.
 * @param   {number} nBits - Number of bits to be used in the key; 128 / 192 / 256.
 * @returns {string} Decrypted text
 *
 * @example
 *   var decr = Aes.Ctr.decrypt('lwGl66VVwVObKIr6of8HVqJr', 'pāşšŵōřđ', 256); // 'big secret'
 */
var decrypt = function(ciphertext, password, nBits) {
    var blockSize = 16;  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
    if (!(nBits==128 || nBits==192 || nBits==256)) throw new Error('Key size is not 128 / 192 / 256');
    ciphertext = String(ciphertext).base64Decode();
    password = String(password).utf8Encode();

    // use AES to encrypt password (mirroring encrypt routine)
    var nBytes = nBits/8;  // no bytes in key
    var pwBytes = new Array(nBytes);
    for (var i=0; i<nBytes; i++) {
        pwBytes[i] = i<password.length ?  password.charCodeAt(i) : 0;
    }
    var key = Cipher(pwBytes, keyExpansion(pwBytes));
    key = key.concat(key.slice(0, nBytes-16));  // expand key to 16/24/32 bytes long

    // recover nonce from 1st 8 bytes of ciphertext
    var counterBlock = new Array(8);
    var ctrTxt = ciphertext.slice(0, 8);
    for (var i=0; i<8; i++) counterBlock[i] = ctrTxt.charCodeAt(i);

    // generate key schedule
    var keySchedule = keyExpansion(key);

    // separate ciphertext into blocks (skipping past initial 8 bytes)
    var nBlocks = Math.ceil((ciphertext.length-8) / blockSize);
    var ct = new Array(nBlocks);
    for (var b=0; b<nBlocks; b++) ct[b] = ciphertext.slice(8+b*blockSize, 8+b*blockSize+blockSize);
    ciphertext = ct;  // ciphertext is now array of block-length strings

    // plaintext will get generated block-by-block into array of block-length strings
    var plaintext = '';

    for (var b=0; b<nBlocks; b++) {
        // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
        for (var c=0; c<4; c++) counterBlock[15-c] = ((b) >>> c*8) & 0xff;
        for (var c=0; c<4; c++) counterBlock[15-c-4] = (((b+1)/0x100000000-1) >>> c*8) & 0xff;

        var cipherCntr = Cipher(counterBlock, keySchedule);  // encrypt counter block

        var plaintxtByte = new Array(ciphertext[b].length);
        for (var i=0; i<ciphertext[b].length; i++) {
            // -- xor plaintext with ciphered counter byte-by-byte --
            plaintxtByte[i] = cipherCntr[i] ^ ciphertext[b].charCodeAt(i);
            plaintxtByte[i] = String.fromCharCode(plaintxtByte[i]);
        }
        plaintext += plaintxtByte.join('');

        // if within web worker, announce progress every 1000 blocks (roughly every 50ms)
        if (typeof WorkerGlobalScope != 'undefined' && self instanceof WorkerGlobalScope) {
            if (b%1000 == 0) self.postMessage({ progress: b/nBlocks });
        }
    }

    plaintext = plaintext.utf8Decode();  // decode from UTF8 back to Unicode multi-byte chars

    return plaintext;
};