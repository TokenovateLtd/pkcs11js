const assert = require("assert");
const os = require("os");
const pkcs11js = require("../");

let softHsmLib;
switch (os.platform()) {
  case "darwin": // macOS
    softHsmLib = "/opt/dpodclient/libs/64/libCryptoki2.so";
    break;
  case "linux":
    softHsmLib = "/opt/dpodclient/libs/64/libCryptoki2.so";
    break;
  case "win32": // Windows
    softHsmLib = "C:\\SoftHSM2\\lib\\softhsm2-x64.dll";
    break;
  default:
    throw new Error("Unsupported platform " + os.platform());
}
const pin = "12345";

const pkcs11 = new pkcs11js.PKCS11();

const deriveMaster = (session, seed)=> {
  const publicKeyTemplate = [
      { type: pkcs11js.CKA_TOKEN, value: true },
      { type: pkcs11js.CKA_PRIVATE, value: true },
      { type: pkcs11js.CKA_ENCRYPT, value: true },
      { type: pkcs11js.CKA_VERIFY, value: true },
      { type: pkcs11js.CKA_DERIVE, value: true },
      { type: pkcs11js.CKA_MODIFIABLE, value: false },
  ];
  const privateKeyTemplate = [
      { type: pkcs11js.CKA_TOKEN, value: true },
      { type: pkcs11js.CKA_PRIVATE, value: true },
      { type: pkcs11js.CKA_DECRYPT, value: true },
      { type: pkcs11js.CKA_SIGN, value: true },
      { type: pkcs11js.CKA_DERIVE, value: true },
      { type: pkcs11js.CKA_MODIFIABLE, value: false },
      { type: pkcs11js.CKA_EXTRACTABLE, value: false },
  ];

  return pkcs11.C_DeriveBIP32Master(session, seed, publicKeyTemplate, privateKeyTemplate);
}

const deriveChild = (session, masterPrivate, path) => {
  const publicKeyTemplate = [
      { type: pkcs11js.CKA_TOKEN, value: false },
      { type: pkcs11js.CKA_PRIVATE, value: true },
      { type: pkcs11js.CKA_VERIFY, value: true },
      { type: pkcs11js.CKA_DERIVE, value: false },
      { type: pkcs11js.CKA_MODIFIABLE, value: false },
  ];
  const privateKeyTemplate = [
      { type: pkcs11js.CKA_TOKEN, value: false },
      { type: pkcs11js.CKA_SENSITIVE, value: true },
      { type: pkcs11js.CKA_PRIVATE, value: true },
      { type: pkcs11js.CKA_SIGN, value: true },
      { type: pkcs11js.CKA_DERIVE, value: false },
      { type: pkcs11js.CKA_MODIFIABLE, value: false },
      { type: pkcs11js.CKA_EXTRACTABLE, value: false },
  ];

  return pkcs11.C_DeriveBIP32Child(session, masterPrivate, publicKeyTemplate, privateKeyTemplate, path);
}

const importSeed = (session, seedHex) => {
  const seed = Buffer.from(seedHex, "hex");
  const aesTemplate = [
    {type: pkcs11js.CKA_TOKEN, value: false},
    {type: pkcs11js.CKA_ENCRYPT, value: true},
    {type: pkcs11js.CKA_UNWRAP, value: true},
    {type: pkcs11js.CKA_PRIVATE, value: true},
    {type: pkcs11js.CKA_VALUE_LEN, value: 32}
  ];

  const wrappingKey = pkcs11.C_GenerateKey(session, { mechanism: pkcs11js.CKM_AES_KEY_GEN }, aesTemplate);

  const parameter = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

  pkcs11.C_EncryptInit(session, { mechanism: pkcs11js.CKM_AES_CBC, parameter }, wrappingKey);

  const encrypted = pkcs11.C_Encrypt(session, seed, Buffer.alloc(200));

  const seedTemplate = [
    { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_SECRET_KEY },
    { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_GENERIC_SECRET },
    { type: pkcs11js.CKA_TOKEN, value: false },
    { type: pkcs11js.CKA_DERIVE, value: true },
    { type: pkcs11js.CKA_PRIVATE, value: true },
    { type: pkcs11js.CKA_EXTRACTABLE, value: false },
    { type: pkcs11js.CKA_MODIFIABLE, value: false },
    { type: pkcs11js.CKA_VALUE_LEN, value: seed.length },
  ];

  return pkcs11.C_UnwrapKey(session, { mechanism: pkcs11js.CKM_AES_CBC, parameter }, wrappingKey, encrypted, seedTemplate);
}

const parsePath = (path) => {
  // Remove the "m/" prefix
  path = path.replace(/^m\//, "");

  // Split the path by "/"
  const split = path.split("/");

  // Create an array to hold the uint32 values
  const pathUints = new Uint32Array(split.length);

  // Parse each component of the path
  split.forEach((index, i) => {
      let x = 0;
      // Check if the index is hardened (ends with "'")
      if (index.endsWith("'")) {
          x = 0x80000000; // Add the hardened flag
          index = index.replace("'", ""); // Remove the "'" character
      }
      // Parse the index as an unsigned integer
      x += parseInt(index, 10);
      pathUints[i] = x;
  });

  return pathUints;
}

const getEcPoint = (session, publicKeyHandle) => {
  return pkcs11.C_GetAttributeValue(session, publicKeyHandle, [{ type: pkcs11js.CKA_EC_POINT }])
    .filter(a => a.type === pkcs11js.CKA_EC_POINT)
    .map(a => a.value)
    .at(0)
}

const loadLibrary = () => {
  pkcs11.load(softHsmLib);
  pkcs11.C_Initialize();
}

const setup = () => {
  loadLibrary();

  const slots = pkcs11.C_GetSlotList(true);
  const slot = slots[0];

  const session = pkcs11.C_OpenSession(slot, pkcs11js.CKF_RW_SESSION | pkcs11js.CKF_SERIAL_SESSION);

  pkcs11.C_Login(session, pkcs11js.CKU_USER, pin);

  return session;
}

const teardown = (session) => {
  pkcs11.C_Logout(session);
  pkcs11.C_CloseSession(session);
}


context("PKCS11", () => {
  let session;

  before(() => {
    session = setup();
  });

  after(() => {
    teardown(session);
  });
  
  context("Luna BIP32", () => {
    const testVectors = [
      ["000102030405060708090a0b0c0d0e0f", "m/0'", "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"],
      ["000102030405060708090a0b0c0d0e0f", "m/0'/1", "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"],
      ["000102030405060708090a0b0c0d0e0f", "m/0'/1/2'", "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2"],
      ["000102030405060708090a0b0c0d0e0f", "m/0'/1/2'/2", "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29"],
      ["000102030405060708090a0b0c0d0e0f", "m/0'/1/2'/2/1000000000", "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"],
      ["fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "m/0", "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"],
      ["fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "m/0/2147483647'", "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b"],
      ["fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "m/0/2147483647'/1", "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9"],
      ["fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "m/0/2147483647'/1/2147483646'", "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0"],
      ["fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "m/0/2147483647'/1/2147483646'/2", "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"],
    ];


    testVectors.forEach(([seedHex, path, expectedPubHex]) => {
      it(`verify key derivation using test vector with path: ${path}`, () => {
        const seed = importSeed(session, seedHex);
        const master = deriveMaster(session, seed);

        const parsedPath = parsePath(path);
        const child = deriveChild(session, master.privateKey, parsedPath);
        let ecPoint = getEcPoint(session, child.publicKey);
        ecPoint = ecPoint.slice(3, 3 + 32);

        let expected = Buffer.from(expectedPubHex, "hex");
        expected = expected.slice(1, expected.length);
        assert.strictEqual(expected.toString('hex'), ecPoint.toString('hex'));
      });
    });
  })
});