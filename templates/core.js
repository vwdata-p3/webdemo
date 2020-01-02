
var base64digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        + "0123456789+/";

function base64encode(data) {
    var s = "";
    var notriples = Math.floor( data.length / 3 );

    for (var i = 0; i < notriples; i++) {
        var value = data.charCodeAt(3*i)*65536 
                    + data.charCodeAt(3*i+1)*256 
                    + data.charCodeAt(3*i+2);
        
        var d4 = value % 64;
        value = Math.floor( value / 64 );
        var d3 = value % 64;
        value = Math.floor( value / 64 );
        var d2 = value % 64;
        value = Math.floor( value / 64 );
        var d1 = value % 64;
        value = Math.floor( value / 64 );

        s += base64digits[d1] + base64digits[d2] 
            + base64digits[d3] + base64digits[d4];
    }

    if (data.length == 3*notriples)
        return s;

    if (data.length == 3*notriples+1) {
        var value = data.charCodeAt(3*notriples) * 16;

        var d2 = value % 64;
        value = Math.floor( value / 64);
        var d1 = value % 64;
        value = Math.floor( value / 64);

        return s + base64digits[d1] + base64digits[d2] + "==";
    }

    var value = data.charCodeAt(3*notriples)*1024 
                + data.charCodeAt(3*notriples+1)*4;

    var d3 = value % 64;
    value = Math.floor( value / 64 );
    var d2 = value % 64;
    value = Math.floor( value / 64 );
    var d1 = value % 64;
    value = Math.floor( value / 64 );

    return s + base64digits[d1] + base64digits[d2] + base64digits[d3] + "=";
}

function base64decode(data) {
    var result = "";
    var length = data.length;
    if (length % 4 != 0)
        throw "base64decode: incorrect padding: string's length is not"
                + " a multiple of four";
    while( data.charAt(length-1)=="=" ) length--;
    var noquartets = Math.floor( length/4 );

    for ( var i = 0; i < noquartets; i++ ) {

        // 'indexOf' is not efficient, but that's not very important to us
        var value = base64digits.indexOf(data.charAt(4*i))*262144;
        value += base64digits.indexOf(data.charAt(4*i+1))*4096;
        value += base64digits.indexOf(data.charAt(4*i+2))*64;
        value += base64digits.indexOf(data.charAt(4*i+3));

        var d3 = value % 256;
        value = Math.floor( value / 256 );
        var d2 = value % 256;
        var d1 = Math.floor( value / 256 );

        result += String.fromCharCode(d1);
        result += String.fromCharCode(d2);
        result += String.fromCharCode(d3);
    }

    if (length == 4*noquartets)
        return result;

    if (length == 4*noquartets + 1)
        throw "base64decode: incorrect padding: '==='";

    if (length == 4*noquartets + 2) {
        var value = base64digits.indexOf(data.charAt(4*i))*262144;
        value += base64digits.indexOf(data.charAt(4*i+1))*4096;

        var d3 = value % 256;
        value = Math.floor( value / 256 );
        var d2 = value % 256;
        var d1 = Math.floor( value / 256 );

        return result + String.fromCharCode(d1);
    }

    if (length == 4*noquartets + 3) {
        var value = base64digits.indexOf(data.charAt(4*i))*262144;
        value += base64digits.indexOf(data.charAt(4*i+1))*4096;
        value += base64digits.indexOf(data.charAt(4*i+2))*64;

        var d3 = value % 256;
        value = Math.floor( value / 256 );
        var d2 = value % 256;
        var d1 = Math.floor( value / 256 );

        return result + String.fromCharCode(d1) + String.fromCharCode(d2);
    }

    throw "assertion failure";
}

console.assert(base64decode(base64encode("a"))=="a");
console.assert(base64decode(base64encode("ab"))=="ab");
console.assert(base64decode(base64encode("abc"))=="abc");
console.assert(base64decode(base64encode("abcd"))=="abcd");

function base64check(str) {
    if (str.length % 4 != 0) 
        return false;

    var i = 0;

    for (var i = 0; i < str.length; i++) {
        if (!base64digits.includes(str.charAt(i)))
            break;
    }

    if (i == str.length)
        return true;

    if (i < str.length-2)
        return false;
    // i == str.length-1 or i == str.length-2 

    if (i == str.length-2) {
        if (str.charAt(str.length-2) != "=" || str.charAt(str.length-1) != "=")
            return false;
        if (base64digits.indexOf(str.charAt(str.length-3)) % 16 != 0)
            return false;
    } else { // i == str.length-1
        if (str.charAt(str.length-1) != "=")
            return false;
        if (base64digits.indexOf(str.charAt(str.length-2)) % 4 != 0)
            return false;
    }

    return true;
}


