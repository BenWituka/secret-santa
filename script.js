import passwords from "./passwords.json" with { type: "json" };
import secrets from "./secrets.json" with { type: "json"}

async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

function hexStringToArrayBuffer(hexString) {
    
  // Ensure even length
  if (hexString.length % 2 !== 0) {
    throw new Error("Hex string must have an even number of characters");
  }

  const uint8array = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < hexString.length; i += 2) {
    uint8array[i / 2] = parseInt(hexString.slice(i, i + 2), 16);
  }
  return uint8array.buffer;
}   

async function deriveAesGcmKey(password, salt) {
  const encoder = new TextEncoder();
  
  // 1. Import password as PBKDF2 key material
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw", 
    encoder.encode(password), 
    { name: "PBKDF2" }, 
    false, 
    ["deriveKey"]
  );

  // 2. Derive the AES-GCM key using PBKDF2
  return await window.crypto.subtle.deriveKey(
    { 
      name: "PBKDF2", 
      salt: encoder.encode(salt), 
      iterations: 100000, 
      hash: "SHA-256" 
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 }, // Specify AES-GCM and 256-bit length
    false, // Key is not extractable
    ["encrypt", "decrypt"] // Key usages
  );
}


async function aesGcmDecode(encrypted, password, iv, salt) {
  const key = await deriveAesGcmKey(password, salt);

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();


  let decrypted;
  try {
    decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: encoder.encode(iv) },
      key,
      hexStringToArrayBuffer(encrypted)
    );
  } catch {
    return "incorrect password";
  }

  return decoder.decode(decrypted);
}

async function aesGcmEncode(secret, password, iv, salt) {
  // 1. Generate a raw AES-GCM key (256-bit)
  const key = await deriveAesGcmKey(password, salt);

  // 2. Encrypt data
  const encoder = new TextEncoder();
  const data = encoder.encode(secret);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: encoder.encode(iv) },
    key,
    data
  );

  return (new Uint8Array(encrypted)).toHex();
}


//produces array of integers representing secret santa draws.
//
function generateDraws(n) {
  let tokens = Array.from(Array(n).keys());
  let draws = [];

  for (let i = 0; i < n; i++) {
      let drawIndex;
      let draw;
      let count = 0;
      //if the last person would draw their own name,
      //start again.
      if (tokens.length === 1 && tokens[0] === i){
        tokens = tokens.concat(draws);
        draws = [];
        i = 0;
      }

      //draw a token, repeat if the person draws their own name.
      do {
          drawIndex = Math.floor(Math.random()*tokens.length);
          draw = tokens[drawIndex];
      } while (draw == i && ++count < 100);
      tokens.splice(drawIndex, 1);
      draws.push(draw);
  }
  return draws;
}

async function generateEncryptedSecrets() {
  let secrets= [];
  const n = passwords.length;
  const draws = generateDraws(passwords.length);

  for(let i = 0; i < n; i++){

    const name = passwords[i].name;
    const password = passwords[i].password;
    const secret = passwords[draws[i]].name;
    const salt = generateSecureRandomString();
    const iv = generateSecureRandomString();
    const encrypted = await aesGcmEncode(secret, password, iv, salt);

    secrets.push({
      name: passwords[i].name,
      salt: salt,
      iv,
      encrypted: encrypted,
    });
  }
  return JSON.stringify(secrets);
}

const generateSecureRandomString = (length = 16) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const randomValues = new Uint8Array(length);
  window.crypto.getRandomValues(randomValues);
  
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(randomValues[i] % chars.length);
  }
  return result;
};   

async function displaySecret() {
  const secretDiv = document.querySelector("#secret");
  const i = +chooserSelect.value;
  const password = passwordInput.value;

  secretDiv.textContent =
    await aesGcmDecode(secrets[i].encrypted, password,
      secrets[i].iv, secrets[i].salt);
}

const chooserSelect = document.querySelector("#chooser");
const passwordInput = document.querySelector("#password");

secrets.forEach((secret, index) => {
  const option = document.createElement("option");
  option.value = index;
  option.textContent = secret.name;
  chooserSelect.append(option);
});

passwordInput.addEventListener('input', displaySecret);
chooserSelect.addEventListener('input', displaySecret);

//if everyone has a password defined in passwords.json
if(
  passwords
    .map(o => o.password !== "")
    .reduce((acc, cur) => acc && cur)
) {
  const secretsDiv = document.querySelector("#secrets");
  secretsDiv.textContent = await generateEncryptedSecrets();
}
