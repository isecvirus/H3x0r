morse = {
    //"": "",
    "A": ".-",
    "B": "-...",
    "C": "-.-.",
    "D": "-..",
    "E": ".",
    "F": "..-.",
    "G": "--.",
    "H": "....",
    "I": "..",
    "J": ".---",
    "K": "-.-",
    "L": ".-..",
    "M": "--",
    "N": "-.",
    "O": "---",
    "P": ".--.",
    "Q": "--.-",
    "R": ".-.",
    "S": "...",
    "T": "-",
    "U": "..-",
    "V": "...-",
    "W": ".--",
    "X": "-..-",
    "Y": "-.--",
    "Z": "--..",
    "0": "-----",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
    "!": "-.-.--",
    '"': ".-..-.",
    "&": ".-...",
    "'": ".----.",
    "(": "-.--.",
    ")": "-.--.-",
    "+": ".-.-.",
    ",": "--..--",
    "-": "-....-",
    ".": ".-.-.-",
    "/": "-..-.",
    ":": "---...",
    ";": "-.-.-.",
    "=": "-...-",
    "?": "..--..",
    "@": ".--.-."
}
let temp_morse = {};

function encode(text=document.getElementById("input").value, separator=document.getElementById("separator").value, space=document.getElementById("space").value) {
    var cipher = []
    // let reg_string = text.replace(new RegExp("\s", space), ""); // re.sub("\s", repl=space, string=text)
    var reg_string = text.split();
    
    for (var i=0;i<reg_string.length;i++) {
        var char = reg_string[i];
            for (var ci=0;ci<char.length;ci++) { // ci=char index
                var c = char[ci].toUpperCase();
                
                if (temp_morse[c] != undefined) { // try to add
                    cipher.push(temp_morse[c]) // the morse code from the character
                } else { // handle the exception if it's not there
                    cipher.push(separator) // add the character as it is.
                }
                
            }
    }
    return cipher.join(space); // then return the encoded string
}

function decode(encoded_morse=document.getElementById("input").value, separator=document.getElementById("separator").value, space=document.getElementById("space").value, unknown=document.getElementById("untranslatable").value) {
    let text = []
    let cipher_array = encoded_morse.split(space);
    cipher_array.filter(chr=>chr); // to remove the empty strings e.g. ""
    

    for (var i=0;i<cipher_array.length;i++) { // spa=space
        let char = cipher_array[i]; // morse code

        if (char === separator) { // if the char is the separator char
            text.push(space);
        } else if (Object.values(temp_morse).includes(char)) { // if there is really a morse char e.g. --- = o/O
            let translated = Object.keys(temp_morse)[Object.values(temp_morse).indexOf(char)];
            text.push(translated);
        } else {
            text.push(unknown);
        }
    }
    return text.join('');
}

function update() {
    Object.assign(temp_morse, morse); // assign the data in morse to temp_morse
    
    Object.keys(temp_morse).forEach(key => {
        temp_morse[key] = temp_morse[key].replace(/\-/g, document.getElementById("dash").value).replace(/\./g, document.getElementById("dot").value);
    });

    const input = document.getElementById("input").value;
    const operation = document.getElementById("operation-type").value;
    const separator = document.getElementById("separator").value;
    const space = document.getElementById("space").value;
    const untranslatable = document.getElementById("untranslatable").value;
    
    if (operation === "Encode") {
        document.getElementById("output").value = encode(input, separator, space, untranslatable);
    } else if (operation === "Decode") {
        document.getElementById("output").value = decode(input, separator, space, untranslatable);
    }
}