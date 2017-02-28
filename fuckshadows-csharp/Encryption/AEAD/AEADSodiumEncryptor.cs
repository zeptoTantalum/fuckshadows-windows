﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
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

        private byte[] _sodiumKey;
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
        }

        protected override int cipherEncrypt(byte[] plaintext, int plen, byte[] ciphertext, ref int clen)
        {
            // buf: all plaintext
            // outbuf: ciphertext + tag
            int ret;
            ulong encClen = 0;
            switch (_cipher) {
                case CIPHER_CHACHA20POLY1305:
                    ret = Sodium.crypto_aead_chacha20poly1305_encrypt(ciphertext, ref encClen,
                                                                      plaintext, (ulong)plen,
                                                                      IntPtr.Zero, 0,
                                                                      IntPtr.Zero, _nonce,
                                                                      _sodiumKey);
                    break;
                case CIPHER_CHACHA20IETFPOLY1305:
                    ret = Sodium.crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, ref encClen,
                                                                           plaintext, (ulong)plen,
                                                                           IntPtr.Zero, 0,
                                                                           IntPtr.Zero, _nonce,
                                                                           _sodiumKey);

                    break;
                default:
                    throw new System.Exception("not implemented");
            }
            if (ret != 0) throw new CryptoErrorException();
            Debug.Assert((int)encClen == plen + tagLen);
            clen = plen + tagLen;
            return ret;
        }

        protected override int cipherDecrypt(byte[] ciphertext, int clen, byte[] plaintext, ref int plen)
        {
            // buf: ciphertext + tag
            // outbuf: plaintext
            int ret;
            ulong decPlen = 0;
            // split tag
            byte[] tagbuf = new byte[tagLen];
            Buffer.BlockCopy(ciphertext, clen - tagLen, tagbuf, 0, tagLen);

            switch (_cipher) {
                case CIPHER_CHACHA20POLY1305:
                    ret = Sodium.crypto_aead_chacha20poly1305_decrypt(plaintext, ref decPlen,
                                                                      IntPtr.Zero,
                                                                      ciphertext, (ulong)clen,
                                                                      IntPtr.Zero, 0,
                                                                      _nonce, _sodiumKey);
                    break;
                case CIPHER_CHACHA20IETFPOLY1305:
                    ret = Sodium.crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, ref decPlen,
                                                                           IntPtr.Zero,
                                                                           ciphertext, (ulong)clen,
                                                                           IntPtr.Zero, 0,
                                                                           _nonce, _sodiumKey);
                    break;
                default:
                    throw new System.Exception("not implemented");
            }

            if (ret != 0) throw new CryptoErrorException();
            Debug.Assert((int)decPlen == clen - tagLen);
            plen = clen - tagLen;
            return ret;
        }

        public override void Dispose() { }
    }
}