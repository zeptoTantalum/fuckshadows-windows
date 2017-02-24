using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Net;
using Cyotek.Collections.Generic;
using Fuckshadows.Encryption.Exception;

namespace Fuckshadows.Encryption.Stream
{
    public abstract class StreamEncryptor
        : EncryptorBase
    {
        protected static byte[] tempbuf = new byte[MAX_INPUT_SIZE];

        // every connection should create its own buffer
        private CircularBuffer<byte> _circularBuffer = new CircularBuffer<byte>(MAX_INPUT_SIZE * 4, false);

        protected Dictionary<string, EncryptorInfo> ciphers;

        protected byte[] _encryptIV;
        protected byte[] _decryptIV;

        // Is first packet
        protected bool _decryptIVReceived;
        protected bool _encryptIVSent;

        protected string _method;
        protected int _cipher;
        // internal name in the crypto library
        protected string _innerLibName;
        protected EncryptorInfo CipherInfo;
        // long-time master key
        protected static byte[] _key = null;
        protected int keyLen;
        protected int ivLen;

        public StreamEncryptor(string method, string password)
            : base(method, password)
        {
            InitEncryptorInfo(method);
            InitKey(password);
        }

        protected abstract Dictionary<string, EncryptorInfo> getCiphers();

        private void InitEncryptorInfo(string method)
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
            ivLen = CipherInfo.IvSize;
        }

        private void InitKey(string password)
        {
            byte[] passbuf = Encoding.UTF8.GetBytes(password);
            if (_key == null) _key = new byte[keyLen];
            if (_key.Length < keyLen) Array.Resize(ref _key, keyLen);
            LegacyDeriveKey(passbuf, _key);
        }

        public static void LegacyDeriveKey(byte[] password, byte[] key)
        {
            byte[] result = new byte[password.Length + 16];
            int i = 0;
            byte[] md5sum = null;
            while (i < key.Length) {
                if (i == 0) {
                    md5sum = MbedTLS.MD5(password);
                } else {
                    md5sum.CopyTo(result, 0);
                    password.CopyTo(result, md5sum.Length);
                    md5sum = MbedTLS.MD5(result);
                }
                md5sum.CopyTo(key, i);
                i += md5sum.Length;
            }
        }

        protected virtual void initCipher(byte[] iv, bool isEncrypt)
        {
            if (isEncrypt) {
                _encryptIV = new byte[ivLen];
                Array.Copy(iv, _encryptIV, ivLen);
            } else {
                _decryptIV = new byte[ivLen];
                Array.Copy(iv, _decryptIV, ivLen);
            }
        }

        protected abstract void cipherUpdate(bool isEncrypt, int length, byte[] buf, byte[] outbuf);

        protected static void randBytes(byte[] buf, int length) { RNG.GetBytes(buf, length); }

        public override void Encrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            if (! _encryptIVSent) {
                // Generate IV
                randBytes(outbuf, ivLen);
                initCipher(outbuf, true);
                _encryptIVSent = true;
                lock (tempbuf) {
                    cipherUpdate(true, length, buf, tempbuf);
                    outlength = length + ivLen;
                    Buffer.BlockCopy(tempbuf, 0, outbuf, ivLen, length);
                }
            } else {
                outlength = length;
                cipherUpdate(true, length, buf, outbuf);
            }
        }

        public override void EncryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            // Generate IV
            randBytes(outbuf, ivLen);
            initCipher(outbuf, true);
            lock (tempbuf) {
                cipherUpdate(true, length, buf, tempbuf);
                outlength = length + ivLen;
                Buffer.BlockCopy(tempbuf, 0, outbuf, ivLen, length);
            }
        }

        public override void Decrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            Debug.Assert(_circularBuffer != null, "_circularBuffer != null");
            _circularBuffer.Put(buf, 0, length);
            if (! _decryptIVReceived) {
                if (_circularBuffer.Size <= ivLen) {
                    // we need more data
                    throw new CryptoNeedMoreException();
                }
                // start decryption
                _decryptIVReceived = true;
                byte[] iv = _circularBuffer.Get(ivLen);
                initCipher(iv, false);
            }
            byte[] cipher = _circularBuffer.Get(_circularBuffer.Size);

            cipherUpdate(false, cipher.Length, cipher, outbuf);
            outlength = cipher.Length;
            // done the decryption
        }

        public override void DecryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            // Get IV from first pos
            initCipher(buf, false);
            outlength = length - ivLen;
            lock (tempbuf) {
                // C# could be multi-threaded
                Buffer.BlockCopy(buf, ivLen, tempbuf, 0, length - ivLen);
                cipherUpdate(false, length - ivLen, tempbuf, outbuf);
            }
        }
    }
}