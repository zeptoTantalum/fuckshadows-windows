using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Fuckshadows.Encryption.Exception;

namespace Fuckshadows.Encryption.AEAD
{
    public class AEADSodiumEncryptor
        : AEADEncryptor, IDisposable
    {
        private const int CIPHER_CHACHA20POLY1305 = 1;
        private const int CIPHER_CHACHA20IETFPOLY1305 = 2;
        private const int CIPHER_XCHACHA20IETFPOLY1305 = 3;

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

        protected override int cipherEncrypt(byte[] key, byte[] plaintext, int plen, byte[] ciphertext, ref int clen)
        {
            // buf: all plaintext
            // outbuf: ciphertext + tag
            byte[] tagbuf = new byte[tagLen];
            int ret;
            switch (_cipher) {
                case CIPHER_CHACHA20POLY1305:
                    ret = Sodium.crypto_aead_chacha20poly1305_encrypt(ciphertext, ref clen,
                                                                      plaintext, plen,
                                                                      IntPtr.Zero, 0,
                                                                      IntPtr.Zero, _nonce,
                                                                      key);
                    break;
                case CIPHER_CHACHA20IETFPOLY1305:
                    ret = Sodium.crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, ref clen,
                                                                           plaintext, plen,
                                                                           IntPtr.Zero, 0,
                                                                           IntPtr.Zero, _nonce,
                                                                           key);

                    break;
                default:
                    throw new System.Exception("not implemented");
            }

            if (ret != 0) throw new CryptoErrorException();
            Buffer.BlockCopy(tagbuf, 0, ciphertext, plen, tagLen);
            clen = plen + tagLen;
            return ret;
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
                case CIPHER_CHACHA20POLY1305:
                    ret = Sodium.crypto_aead_chacha20poly1305_decrypt(plaintext, ref plen,
                                                                      IntPtr.Zero,
                                                                      ciphertext, clen,
                                                                      IntPtr.Zero, 0,
                                                                      _nonce, key);
                    break;
                case CIPHER_CHACHA20IETFPOLY1305:
                    ret = Sodium.crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, ref plen,
                                                                           IntPtr.Zero,
                                                                           ciphertext, clen,
                                                                           IntPtr.Zero, 0,
                                                                           _nonce, key);
                    break;
                default:
                    throw new System.Exception("not implemented");
            }

            if (ret != 0) throw new CryptoErrorException();
            plen = clen - tagLen;
            return ret;
        }

        public override void Dispose() { }
    }
}