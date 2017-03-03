using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Fuckshadows.Controller;
using Fuckshadows.Encryption.Exception;

namespace Fuckshadows.Encryption.AEAD
{
    public class AEADSodiumEncryptor
        : AEADEncryptor, IDisposable
    {
        private const int CIPHER_CHACHA20POLY1305 = 1;
        private const int CIPHER_CHACHA20IETFPOLY1305 = 2;
        private const int CIPHER_XCHACHA20IETFPOLY1305 = 3;

        private byte[] _sodiumKey = null;

        public AEADSodiumEncryptor(string method, string password)
            : base(method, password) { }

        private static Dictionary<string, EncryptorInfo> _ciphers = new Dictionary<string, EncryptorInfo>
        {
            { "chacha20-poly1305", new EncryptorInfo(32, 32, 8, 16, CIPHER_CHACHA20POLY1305) },
            { "chacha20-ietf-poly1305", new EncryptorInfo(32, 32, 12, 16, CIPHER_CHACHA20IETFPOLY1305) },
            { "xchacha20-ietf-poly1305", new EncryptorInfo(32, 32, 24, 16, CIPHER_XCHACHA20IETFPOLY1305) },
        };

        public static List<string> SupportedCiphers() { return new List<string>(_ciphers.Keys); }

        protected override Dictionary<string, EncryptorInfo> getCiphers() { return _ciphers; }

        public override void InitCipher(byte[] salt, bool isEncrypt, bool isUdp)
        {
            base.InitCipher(salt, isEncrypt, isUdp);
            if (isUdp) {
                _sodiumKey = _Masterkey;
            }
            else
            {
                DeriveSessionKey(isEncrypt ? _encryptSalt : _decryptSalt,
                    _Masterkey, _sessionKey);
                _sodiumKey = _sessionKey;
            }
            Logging.Dump("_sodiumKey", _sodiumKey, keyLen);
        }

        public override int cipherEncrypt(byte[] plaintext, int plen, byte[] ciphertext, ref int clen)
        {
            Debug.Assert(_sodiumKey != null);
            // buf: all plaintext
            // outbuf: ciphertext + tag
            int ret;
            ulong encClen = 0;
            Logging.Dump("_encNonce before enc", _encNonce, nonceLen);
            Logging.Dump("before cipherEncrypt: plain", plaintext, plen);
            switch (_cipher) {
                case CIPHER_CHACHA20POLY1305:
                    ret = Sodium.crypto_aead_chacha20poly1305_encrypt(ciphertext, ref encClen,
                                                                      plaintext, (ulong)plen,
                                                                      IntPtr.Zero, 0,
                                                                      IntPtr.Zero, _encNonce,
                                                                      _sodiumKey);
                    break;
                case CIPHER_CHACHA20IETFPOLY1305:
                    ret = Sodium.crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, ref encClen,
                                                                           plaintext, (ulong)plen,
                                                                           IntPtr.Zero, 0,
                                                                           IntPtr.Zero, _encNonce,
                                                                           _sodiumKey);

                    break;
                default:
                    throw new System.Exception("not implemented");
            }
            if (ret != 0) throw new CryptoErrorException();
            Logging.Dump("after cipherEncrypt: cipher", ciphertext, (int)encClen);
            clen = (int)encClen;
            return ret;
        }

        public override int cipherDecrypt(byte[] ciphertext, int clen, byte[] plaintext, ref int plen)
        {
            Debug.Assert(_sodiumKey != null);
            // buf: ciphertext + tag
            // outbuf: plaintext
            int ret;
            ulong decPlen = 0;
            Logging.Dump("_decNonce before dec", _decNonce, nonceLen);
            Logging.Dump("before cipherDecrypt: cipher", ciphertext, clen);
            switch (_cipher) {
                case CIPHER_CHACHA20POLY1305:
                    ret = Sodium.crypto_aead_chacha20poly1305_decrypt(plaintext, ref decPlen,
                                                                      IntPtr.Zero,
                                                                      ciphertext, (ulong)clen,
                                                                      IntPtr.Zero, 0,
                                                                      _decNonce, _sodiumKey);
                    break;
                case CIPHER_CHACHA20IETFPOLY1305:
                    ret = Sodium.crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, ref decPlen,
                                                                           IntPtr.Zero,
                                                                           ciphertext, (ulong)clen,
                                                                           IntPtr.Zero, 0,
                                                                           _decNonce, _sodiumKey);
                    break;
                default:
                    throw new System.Exception("not implemented");
            }

            if (ret != 0) throw new CryptoErrorException();
            Logging.Dump("after cipherDecrypt: plain", plaintext, (int)decPlen);
            plen = (int)decPlen;
            return ret;
        }

        public override void Dispose() { }
    }
}