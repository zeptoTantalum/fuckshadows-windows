using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Fuckshadows.Encryption.AEAD
{
    public class AEADMbedTLSEncryptor:AEADEncryptor,IDisposable
    {
        const int CIPHER_AES = 1;

        private IntPtr _encryptCtx = IntPtr.Zero;
        private IntPtr _decryptCtx = IntPtr.Zero;

        public AEADMbedTLSEncryptor(string method, string password)
            : base(method, password)
        {
        }

        private static Dictionary<string, EncryptorInfo> _ciphers = new Dictionary<string, EncryptorInfo> {
            { "aes-128-gcm", new EncryptorInfo("AES-128-GCM", 16, 16, 16, CIPHER_AES) },
            { "aes-192-gcm", new EncryptorInfo("AES-192-GCM", 24, 16, 16, CIPHER_AES) },
            { "aes-256-gcm", new EncryptorInfo("AES-256-GCM", 32, 16, 16, CIPHER_AES) },
        };

        public static List<string> SupportedCiphers()
        {
            return new List<string>(_ciphers.Keys);
        }

        protected override Dictionary<string, EncryptorInfo> getCiphers()
        {
            return _ciphers;
        }

        protected override void cipherEncrypt(bool isCipher, int length, byte[] buf, byte[] outbuf)
        {
            throw new NotImplementedException();
        }

        protected override void cipherDecrypt(bool isCipher, int length, byte[] buf, byte[] ourbuf)
        {
            throw new NotImplementedException();
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

        ~AEADMbedTLSEncryptor()
        {
            Dispose(false);
        }

        protected virtual void Dispose(bool disposing)
        {
            lock (_lock)
            {
                if (_disposed) return;
                _disposed = true;
            }

            if (disposing)
            {
                // free managed objects
            }

            // free unmanaged objects
            if (_encryptCtx != IntPtr.Zero)
            {
                MbedTLS.cipher_free(_encryptCtx);
                Marshal.FreeHGlobal(_encryptCtx);
                _encryptCtx = IntPtr.Zero;
            }
            if (_decryptCtx != IntPtr.Zero)
            {
                MbedTLS.cipher_free(_decryptCtx);
                Marshal.FreeHGlobal(_decryptCtx);
                _decryptCtx = IntPtr.Zero;
            }
        }

        #endregion
    }
}
