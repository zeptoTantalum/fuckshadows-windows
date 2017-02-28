using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cyotek.Collections.Generic;
using Fuckshadows.Encryption;
using Fuckshadows.Encryption.Exception;

namespace Fuckshadows.Encryption.AEAD
{
    public abstract class AEADEncryptor
        : EncryptorBase
    {
        // We are using the same saltLen and keyLen

        private const string Personal = "fuckshadows-g3nk";
        private static readonly byte[] PersonalBytes = Encoding.ASCII.GetBytes(Personal);

        protected static byte[] tempbuf = new byte[MAX_INPUT_SIZE];

        // every connection should create its own buffer
        private CircularBuffer<byte> _circularBuffer = new CircularBuffer<byte>(MAX_INPUT_SIZE * 2, false);

        private const int CHUNK_LEN_BYTES = 2;
        private const int CHUNK_LEN_MASK = 0x3FFF;

        protected Dictionary<string, EncryptorInfo> ciphers;

        protected string _method;
        protected int _cipher;
        // internal name in the crypto library
        protected string _innerLibName;
        protected EncryptorInfo CipherInfo;
        protected static byte[] _Masterkey = null;
        protected byte[] _sessionKey;
        protected int keyLen;
        protected int saltLen;
        protected int tagLen;
        protected int nonceLen;

        protected byte[] _encryptSalt;
        protected byte[] _decryptSalt;

        protected byte[] _nonce;
        // Is first packet
        protected bool _decryptSaltReceived;
        protected bool _encryptSaltSent;

        public AEADEncryptor(string method, string password)
            : base(method, password)
        {
            InitEncryptorInfo(method);
            InitKey(password);
            // Initialize all-zero nonce for each connection
            _nonce = new byte[nonceLen];
        }

        protected abstract Dictionary<string, EncryptorInfo> getCiphers();

        protected void InitEncryptorInfo(string method)
        {
            method = method.ToLower();
            _method = method;
            ciphers = getCiphers();
            CipherInfo = ciphers[_method];
            _innerLibName = CipherInfo.InnerLibName;
            _cipher = CipherInfo.Type;
            if (_cipher == 0) {
                throw new System.Exception("method not found");
            }
            keyLen = CipherInfo.KeySize;
            saltLen = CipherInfo.SaltSize;
            tagLen = CipherInfo.TagSize;
            nonceLen = CipherInfo.NonceSize;
        }

        protected void InitKey(string password)
        {
            byte[] passbuf = Encoding.UTF8.GetBytes(password);
            if (_Masterkey == null) _Masterkey = new byte[keyLen];
            if (_Masterkey.Length < keyLen) Array.Resize(ref _Masterkey, keyLen);
            DeriveKey(passbuf, _Masterkey);

        }

        public void DeriveKey(byte[] password, byte[] key)
        {
            int ret = Sodium.crypto_generichash(key, keyLen, password, (ulong) password.Length, IntPtr.Zero, 0);
            if (ret != 0) throw new System.Exception("failed to generate hash");
        }

        public void DeriveSessionKey(byte[] salt, byte[] masterKey, byte[] sessionKey)
        {
            int ret = Sodium.crypto_generichash_blake2b_salt_personal(sessionKey, keyLen, IntPtr.Zero, 0, masterKey,
                                                                      keyLen, salt, PersonalBytes);
            if (ret != 0) throw new System.Exception("failed to generate session key");
        }

        protected void IncrementNonce()
        {
                Sodium.sodium_increment(_nonce, nonceLen);
        }

        protected virtual void InitCipher(byte[] salt, bool isEncrypt, bool isUdp)
        {
            if (isEncrypt) {
                _encryptSalt = new byte[saltLen];
                Array.Copy(salt, _encryptSalt, saltLen);
            } else {
                _decryptSalt = new byte[saltLen];
                Array.Copy(salt, _decryptSalt, saltLen);
            }
        }

        public static void randBytes(byte[] buf, int length) { RNG.GetBytes(buf, length); }

        protected abstract int cipherEncrypt(byte[] plaintext, int plen, byte[] ciphertext, ref int clen);

        protected abstract int cipherDecrypt(byte[] ciphertext, int clen, byte[] plaintext, ref int plen);

        #region API for other module

        public override void Encrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            if (! _encryptSaltSent) {
                // Generate salt
                randBytes(outbuf, saltLen);
                InitCipher(outbuf, true, false);
                _encryptSaltSent = true;
                lock (tempbuf) {
                    //cipherEncrypt(false, length, buf, tempbuf);
                    outlength = length + tagLen * 2 + saltLen + CHUNK_LEN_BYTES;
                    Buffer.BlockCopy(tempbuf, 0, outbuf, saltLen, length);
                }
            } else {
                outlength = length + tagLen * 2 + CHUNK_LEN_BYTES;
                //cipherEncrypt(false, length, buf, outbuf);
            }
        }

        public override void EncryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            // Generate salt
            randBytes(outbuf, saltLen);
            InitCipher(outbuf, true, true);
            lock (tempbuf) {
                //cipherEncrypt(true, length, buf, tempbuf);
                outlength = length + tagLen + saltLen;
                Buffer.BlockCopy(tempbuf, 0, outbuf, saltLen, length);
            }
        }

        public override void Decrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            Debug.Assert(_circularBuffer != null, "_circularBuffer != null");
            // drop all into buffer
            _circularBuffer.Put(buf, 0, length);
            if (! _decryptSaltReceived) {
                // check if we get all of them
                if (_circularBuffer.Size <= saltLen) {
                    // need more
                    outlength = 0;
                    return;
                }
                _decryptSaltReceived = true;
                byte[] salt = _circularBuffer.Get(saltLen);
                InitCipher(salt, false, false);
            }
            // handle chunks
            throw new NotImplementedException();
        }

        public override void DecryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength) { throw new NotImplementedException(); }

        #endregion

        #region Private handling

        protected void ChunkEncrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            throw new NotImplementedException();
        }

        protected void ChunkDecrypt(byte[] buf, int length, byte[] outbuf, out int outlength) { throw new NotImplementedException(); }

        #endregion
    }
}