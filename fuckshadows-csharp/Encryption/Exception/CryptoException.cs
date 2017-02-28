namespace Fuckshadows.Encryption.Exception
{
    internal class CryptoNeedMoreException : System.Exception
    {
        internal CryptoNeedMoreException()
        {
        }

        internal CryptoNeedMoreException(string msg) : base(msg)
        {
        }

        internal CryptoNeedMoreException(string message, System.Exception innerException) : base(message, innerException)
        {
        }
    }

    public class CryptoErrorException : System.Exception
    {
        public CryptoErrorException()
        {
        }

        public CryptoErrorException(string msg) : base(msg)
        {
        }

        public CryptoErrorException(string message, System.Exception innerException) : base(message, innerException)
        {
        }
    }
}