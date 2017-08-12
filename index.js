var aes = require('browserify-aes')
var assert = require('assert')
var bs58check = require('bs58check')
var createHash = require('create-hash')
var scrypt = require('scryptsy')
var xor = require('buffer-xor')
var ecurve = require('ecurve')

const curve = ecurve.getCurveByName('secp256r1')
var BigInteger = require('bigi')

// constants
const SCRYPT_PARAMS = {
  N: 16384, // specified by NEP2
  r: 8,
  p: 8
}
const NULL = new Buffer(0)

function hash160 (buffer) {
  return createHash('rmd160').update(
    createHash('sha256').update(buffer).digest()
  ).digest()
}

function hash256 (buffer) {
  return createHash('sha256').update(
    createHash('sha256').update(buffer).digest()
  ).digest()
}

function getAddress (privateKey) {
  let privateKeyBuffer = new BigInteger.fromHex(privateKey)
  let Q = curve.G.multiply(privateKey).getEncoded(true).toString('hex')
  let publickey = '21' + Q + 'ac'
  let riphash = '17' + hash160(hash256(Buffer.fromHex(Q))).toString('hex')
  let shahash = hash256(Buffer.fromHex(riphash)).toString('hex')
  
  let shaChecksum = toArrayBuffer(shahash.substring(0, 8))
  // Construct RIPEMD buffer
  const ripBuffer = toArrayBuffer(riphash)
  // Construct 25 byte Address Buffer
  let addrBuffer = new Uint8Array(25)
  addrBuffer.set(ripBuffer,0)
  addrBuffer.set(shaChecksum,21)
  return bs58check.encode(addrBuffer)
}


function encryptRaw (buffer, passphrase, progressCallback, scryptParams) {
  if (buffer.length !== 32) throw new Error('Invalid private key length')
  scryptParams = scryptParams || SCRYPT_PARAMS

  var address = getAddress(buffer)
  var secret = new Buffer(passphrase, 'utf8')
  var salt = hash256(address).slice(0, 4)

  var N = scryptParams.N
  var r = scryptParams.r
  var p = scryptParams.p

  var scryptBuf = scrypt(secret, salt, N, r, p, 64, progressCallback)
  var derivedHalf1 = scryptBuf.slice(0, 32)
  var derivedHalf2 = scryptBuf.slice(32, 64)

  var xorBuf = xor(buffer, derivedHalf1)
  var cipher = aes.createCipheriv('aes-256-ecb', derivedHalf2, NULL)
  cipher.setAutoPadding(false)
  cipher.end(xorBuf)

  var cipherText = cipher.read()

  // 0x01 | 0x42 | flagByte | salt (4) | cipherText (32)
  var result = new Buffer(7 + 32)
  result.writeUInt8(0x01, 0)
  result.writeUInt8(0x42, 1)
  result.writeUInt8(0xe0, 2)
  salt.copy(result, 3)
  cipherText.copy(result, 7)

  return result
}

function encrypt (buffer, passphrase, progressCallback, scryptParams) {
  return bs58check.encode(encryptRaw(buffer, passphrase, progressCallback, scryptParams))
}

// some of the techniques borrowed from: https://github.com/pointbiz/bitaddress.org
function decryptRaw (buffer, passphrase, progressCallback, scryptParams) {
  // 39 bytes: 2 bytes prefix, 37 bytes payload
  if (buffer.length !== 39) throw new Error('Invalid NEP2 data length')
  if (buffer.readUInt8(0) !== 0x01) throw new Error('Invalid NEP2 prefix')
  scryptParams = scryptParams || SCRYPT_PARAMS

  var type = buffer.readUInt8(1)
  if (type !== 0x42) throw new Error('Invalid NEP2 type')

  passphrase = new Buffer(passphrase, 'utf8')

  var flagByte = buffer.readUInt8(2)

  var N = scryptParams.N
  var r = scryptParams.r
  var p = scryptParams.p

  var salt = buffer.slice(3, 7)
  var scryptBuf = scrypt(passphrase, salt, N, r, p, 64, progressCallback)
  var derivedHalf1 = scryptBuf.slice(0, 32)
  var derivedHalf2 = scryptBuf.slice(32, 64)

  var privKeyBuf = buffer.slice(7, 7 + 32)
  var decipher = aes.createDecipheriv('aes-256-ecb', derivedHalf2, NULL)
  decipher.setAutoPadding(false)
  decipher.end(privKeyBuf)

  var plainText = decipher.read()
  var privateKey = xor(plainText, derivedHalf1)

  // verify salt matches address
  var address = getAddress(privateKey)
  var checksum = hash256(address).slice(0, 4)
  assert.deepEqual(salt, checksum)

  return privateKey
}

function decrypt (string, passphrase, progressCallback, scryptParams) {
  return decryptRaw(bs58check.decode(string), passphrase, progressCallback, scryptParams)
}

function verify (string) {
  var decoded = bs58check.decodeUnsafe(string)
  if (!decoded) return false

  if (decoded.length !== 39) return false
  if (decoded.readUInt8(0) !== 0x01) return false

  var type = decoded.readUInt8(1)
  var flag = decoded.readUInt8(2)

  // encrypted WIF
  if (type !== 0x42) return false
  if (flag !== 0xe0) return false

  return true
}

module.exports = {
  getAddress: getAddress,
  decrypt: decrypt,
  encrypt: encrypt,
  verify: verify
}
