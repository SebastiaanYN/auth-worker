const ALGORITHM = {
  name: "RSASSA-PKCS1-v1_5",
  modulusLength: 4096,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  hash: "SHA-256",
};

function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

export async function generate_pem() {
  let keyPair = await crypto.subtle.generateKey(ALGORITHM, true, [
    "sign",
    "verify",
  ]);

  const key = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const str = ab2str(key);
  const base64 = btoa(str);
  const newlines = base64.match(/.{1,64}/g).join("\n");
  const pem = `-----BEGIN PRIVATE KEY-----\n${newlines}\n-----END PRIVATE KEY-----`;

  return pem;
}
