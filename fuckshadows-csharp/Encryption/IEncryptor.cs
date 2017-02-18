using System;

namespace Fuckshadows.Encryption
{
    public interface IEncryptor : IDisposable
    {
        void Encrypt(byte[] buf, int length, byte[] outbuf, out int outlength);
        void Decrypt(byte[] buf, int length, byte[] outbuf, out int outlength);
        void EncryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength);
        void DecryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength);
    }
}
