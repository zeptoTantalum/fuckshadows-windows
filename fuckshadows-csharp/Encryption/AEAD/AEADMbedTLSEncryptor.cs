using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Fuckshadows.Encryption.Exception;

namespace Fuckshadows.Encryption.AEAD
{
    public class AEADMbedTLSEncryptor
        : AEADEncryptor, IDisposable
    {
        const int CIPHER_AES = 1;

        private IntPtr _encryptCtx = IntPtr.Zero;
        private IntPtr _decryptCtx = IntPtr.Zero;

        public AEADMbedTLSEncryptor(string method, string password)
            : base(method, password) { }

        private static Dictionary<string, EncryptorInfo> _ciphers = new Dictionary<string, EncryptorInfo>
        {
            { "aes-128-gcm", new EncryptorInfo("AES-128-GCM", 16, 16, 12, 16, CIPHER_AES) },
            { "aes-192-gcm", new EncryptorInfo("AES-192-GCM", 24, 24, 12, 16, CIPHER_AES) },
            { "aes-256-gcm", new EncryptorInfo("AES-256-GCM", 32, 32, 12, 16, CIPHER_AES) },
        };

        public static List<string> SupportedCiphers() { return new List<string>(_ciphers.Keys); }

        protected override Dictionary<string, EncryptorInfo> getCiphers() { return _ciphers; }

        protected override void InitCipher(byte[] salt, bool isCipher, bool isUdp)
        {
            base.InitCipher(salt, isCipher, isUdp);
            IntPtr ctx = Marshal.AllocHGlobal(MbedTLS.cipher_get_size_ex());
            if (isCipher) {
                _encryptCtx = ctx;
            } else {
                _decryptCtx = ctx;
            }
            MbedTLS.cipher_init(ctx);
            if (MbedTLS.cipher_setup(ctx, MbedTLS.cipher_info_from_string(_innerLibName)) != 0)
                throw new System.Exception("Cannot initialize mbed TLS cipher context");

            if (isUdp) {
                CipherSetKey(isCipher, _Masterkey);
            } else {
                DeriveSessionKey(isCipher ? _encryptSalt : _decryptSalt,
                    _Masterkey, _sessionKey);
                CipherSetKey(isCipher, _sessionKey);
            }
        }

        // UDP: master key
        // TCP: session key
        private void CipherSetKey(bool isCipher, byte[] key)
        {
            IntPtr ctx = isCipher ? _encryptCtx : _decryptCtx;
            int ret = MbedTLS.cipher_setkey(ctx, key, keyLen * 8, isCipher ? MbedTLS.MBEDTLS_ENCRYPT : MbedTLS.MBEDTLS_DECRYPT);
            if (ret != 0) throw new System.Exception("failed to set key");
            ret = MbedTLS.cipher_reset(ctx);
            if (ret != 0) throw new System.Exception("failed to finish preparation");
        }

        protected override int cipherEncrypt(byte[] key, byte[] plaintext, int plen, byte[] ciphertext, ref int clen)
        {
            // buf: all plaintext
            // outbuf: ciphertext + tag
            int ret;
            byte[] tagbuf = new byte[tagLen];
            switch (_cipher) {
                case CIPHER_AES:
                    ret = MbedTLS.cipher_auth_encrypt(_encryptCtx,
                                                      _nonce, nonceLen,
                                                      IntPtr.Zero, 0,
                                                      plaintext, plen,
                                                      ciphertext, ref plen,
                                                      tagbuf, tagLen);
                    if (ret != 0) throw new CryptoErrorException();

                    Buffer.BlockCopy(tagbuf, 0, ciphertext, plen, tagLen);
                    clen = plen + tagLen;
                    return ret;
                default:
                    throw new System.Exception("not implemented");
            }
        }

        protected override int cipherDecrypt(byte[] key, byte[] ciphertext, int clen, byte[] plaintext, ref int plen)
        {
            // buf: ciphertext + tag
            // outbuf: plaintext
            int ret;
            // split tag
            byte[] tagbuf = new byte[tagLen];
            Buffer.BlockCopy(ciphertext, clen - tagLen, tagbuf, 0, tagLen);
            switch (_cipher) {
                case CIPHER_AES:
                    ret = MbedTLS.cipher_auth_decrypt(_decryptCtx,
                                                      _nonce, nonceLen,
                                                      IntPtr.Zero, 0,
                                                      ciphertext, clen - tagLen,
                                                      plaintext, ref plen,
                                                      tagbuf, tagLen);
                    if (ret != 0) throw new CryptoErrorException();

                    plen = clen - tagLen;
                    return ret;
                default:
                    throw new System.Exception("not implemented");
            }
        }

        #region IDisposable

        private bool _disposed;

        // instance based lock
        private readonly object _lock = new object();

        public override void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~AEADMbedTLSEncryptor() { Dispose(false); }

        protected virtual void Dispose(bool disposing)
        {
            lock (_lock) {
                if (_disposed) return;
                _disposed = true;
            }

            if (disposing) {
                // free managed objects
            }

            // free unmanaged objects
            if (_encryptCtx != IntPtr.Zero) {
                MbedTLS.cipher_free(_encryptCtx);
                Marshal.FreeHGlobal(_encryptCtx);
                _encryptCtx = IntPtr.Zero;
            }
            if (_decryptCtx != IntPtr.Zero) {
                MbedTLS.cipher_free(_decryptCtx);
                Marshal.FreeHGlobal(_decryptCtx);
                _decryptCtx = IntPtr.Zero;
            }
        }

        #endregion
    }
}