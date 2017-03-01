using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
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

        // for UDP only
        protected static byte[] _udpTmpBuf = new byte[MAX_INPUT_SIZE];

        // every connection should create its own buffer
        private CircularBuffer<byte> _decCircularBuffer = new CircularBuffer<byte>(MAX_INPUT_SIZE * 2, false);
        private CircularBuffer<byte> _encCircularBuffer = new CircularBuffer<byte>(MAX_INPUT_SIZE * 2, false);

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

        // Is first chunk(tcp request)
        protected bool _tcpRequestSent;

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
            // init master key
            if (_Masterkey == null) _Masterkey = new byte[keyLen];
            if (_Masterkey.Length < keyLen) Array.Resize(ref _Masterkey, keyLen);
            DeriveKey(passbuf, _Masterkey);
            // init session key
            if (_sessionKey == null) _sessionKey = new byte[keyLen];
            if (_sessionKey.Length < keyLen) Array.Resize(ref _sessionKey, keyLen);
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

        protected void IncrementNonce() { Sodium.sodium_increment(_nonce, nonceLen); }

        public virtual void InitCipher(byte[] salt, bool isEncrypt, bool isUdp)
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

        #region TCP

        public override void Encrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            Debug.Assert(_encCircularBuffer != null, "_encCircularBuffer != null");
            _encCircularBuffer.Put(buf, 0, length);
            int cipherOffset = 0;
            outlength = 0;
            if (! _encryptSaltSent) {
                // Generate salt
                byte[] saltBytes = new byte[saltLen];
                randBytes(saltBytes, saltLen);
                InitCipher(saltBytes, true, false);
                Buffer.BlockCopy(saltBytes, 0, outbuf, 0, saltLen);
                cipherOffset = saltLen;
                outlength = saltLen;
                _encryptSaltSent = true;
            }

            if (! _tcpRequestSent) {
                // The first TCP request
                int encAddrBufLength;
                byte[] encAddrBufBytes = new byte[AddrBufLength + tagLen * 2 + CHUNK_LEN_BYTES];
                byte[] addrBytes = new byte[AddrBufLength];
                Buffer.BlockCopy(AddrBufBytes, 0, addrBytes, 0, AddrBufLength);

                ChunkEncrypt(addrBytes, AddrBufLength, encAddrBufBytes, out encAddrBufLength);
                Debug.Assert(encAddrBufLength == AddrBufLength + tagLen * 2 + CHUNK_LEN_BYTES);
                Buffer.BlockCopy(encAddrBufBytes, 0, outbuf, cipherOffset, encAddrBufLength);
                cipherOffset += encAddrBufLength;
                // skip address buffer
                _encCircularBuffer.Skip(AddrBufLength);
                outlength += encAddrBufLength;
                _tcpRequestSent = true;
            }

            // handle other chunks
            while (true) {
                int chunklength = Math.Min(CHUNK_LEN_MASK, _encCircularBuffer.Size);
                if (chunklength <= 0) {
                    // not enough data to encrypt, we can leave safely
                    return;
                }
                byte[] chunkBytes = _encCircularBuffer.Get(chunklength);
                int encChunkLength;
                byte[] encChunkBytes = new byte[chunklength + tagLen * 2 + CHUNK_LEN_BYTES];
                ChunkEncrypt(chunkBytes, chunklength, encChunkBytes, out encChunkLength);
                Debug.Assert(encChunkLength == chunklength + tagLen * 2 + CHUNK_LEN_BYTES);
                Buffer.BlockCopy(encChunkBytes, 0, outbuf, cipherOffset, encChunkLength);
                outlength += encChunkLength;
                cipherOffset += encChunkLength;
            }
        }

        public override void Decrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            Debug.Assert(_decCircularBuffer != null, "_decCircularBuffer != null");
            int plainOffset = 0;
            outlength = 0;
            // drop all into buffer
            _decCircularBuffer.Put(buf, 0, length);
            if (! _decryptSaltReceived) {
                // check if we get all of them
                if (_decCircularBuffer.Size <= saltLen) {
                    // need more
                    return;
                }
                _decryptSaltReceived = true;
                byte[] salt = _decCircularBuffer.Get(saltLen);
                InitCipher(salt, false, false);
                _decryptSaltReceived = true;
            }

            // handle chunks
            while (true) {
                // check if we already done all of them
                if (_decCircularBuffer.Size <= 0) return;

                // first get chunk length
                if (_decCircularBuffer.Size <= CHUNK_LEN_BYTES + tagLen) {
                    // so we only have length tag?
                    return;
                }
                byte[] encLenBytes = _decCircularBuffer.Peek(CHUNK_LEN_BYTES + tagLen);
                int decChunkLenLength = - 1;
                byte[] decChunkLenBytes = new byte[CHUNK_LEN_BYTES];
                // try to dec chunk len
                cipherDecrypt(encLenBytes, CHUNK_LEN_BYTES + tagLen, decChunkLenBytes, ref decChunkLenLength);
                Debug.Assert(decChunkLenLength == CHUNK_LEN_BYTES);
                IncrementNonce();
                // finally we get the real chunk len
                int chunkLen = IPAddress.NetworkToHostOrder((short) BitConverter.ToUInt16(decChunkLenBytes, 0));
                if (_decCircularBuffer.Size < CHUNK_LEN_BYTES + tagLen /* we haven't remove them */+ chunkLen + tagLen) {
                    return;
                }
                // we have enough data to decrypt one chunk
                // drop chunk len and its tag from buffer
                _decCircularBuffer.Skip(CHUNK_LEN_BYTES + tagLen);
                byte[] encChunkBytes = _decCircularBuffer.Get(chunkLen + tagLen);
                byte[] decChunkBytes = new byte[chunkLen];
                int decChunkLen = - 1;
                cipherDecrypt(encChunkBytes, chunkLen + tagLen, decChunkBytes, ref decChunkLen);
                Debug.Assert(decChunkLen == chunkLen);
                IncrementNonce();

                // output to outbuf
                Buffer.BlockCopy(decChunkBytes, 0, outbuf, plainOffset, decChunkLen);
                plainOffset += decChunkLen;
                outlength += decChunkLen;
            }
        }

        #endregion

        #region UDP

        public override void EncryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            // Generate salt
            randBytes(outbuf, saltLen);
            InitCipher(outbuf, true, true);
            int olen = - 1;
            lock (_udpTmpBuf) {
                cipherEncrypt(buf, length, _udpTmpBuf, ref olen);
                Debug.Assert(olen == length + tagLen);
                Buffer.BlockCopy(_udpTmpBuf, 0, outbuf, saltLen, olen);
                outlength = saltLen + olen;
            }
        }

        public override void DecryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            InitCipher(buf, false, true);
            int olen = - 1;
            lock (_udpTmpBuf) {
                // copy remaining data to first pos
                Buffer.BlockCopy(buf, saltLen, buf, 0, length - saltLen);
                cipherDecrypt(buf, length - saltLen, _udpTmpBuf, ref olen);
                Buffer.BlockCopy(_udpTmpBuf, 0, outbuf, 0, olen);
                outlength = olen;
            }
        }

        #endregion

        // we know the plaintext length before encryption, so we can do it in one operation
        private void ChunkEncrypt(byte[] plaintext, int plainLen, byte[] ciphertext, out int cipherLen)
        {
            // we already make sure chunk length is less or equal to CHUNK_LEN_MASK
            int chunkLen = plainLen;
            byte[] encLenBytes = new byte[CHUNK_LEN_BYTES + tagLen];
            byte[] encBytes = new byte[chunkLen + tagLen];
            int encChunkLenLength = - 1;
            int encBufLength = - 1;
            byte[] lenbuf = BitConverter.GetBytes((ushort) IPAddress.HostToNetworkOrder((short) chunkLen));

            // encrypt len
            cipherEncrypt(lenbuf, 2, encLenBytes, ref encChunkLenLength);
            Debug.Assert(encChunkLenLength == CHUNK_LEN_BYTES + tagLen);
            IncrementNonce();

            // encrypt corresponding data
            cipherEncrypt(plaintext, chunkLen, encBytes, ref encBufLength);
            Debug.Assert(encBufLength == chunkLen + tagLen);
            IncrementNonce();

            // construct outbuf
            Buffer.BlockCopy(encLenBytes, 0, ciphertext, 0, encChunkLenLength);
            Buffer.BlockCopy(encBytes, 0, ciphertext, encChunkLenLength, encBufLength);
            cipherLen = encChunkLenLength + encBufLength;
        }
    }
}