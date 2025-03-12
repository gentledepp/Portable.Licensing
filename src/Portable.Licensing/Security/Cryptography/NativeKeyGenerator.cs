#if NET5_0 || NET6_0 || NET7_0 || NET8_0 || NET9_0
using System.Security.Cryptography;

namespace Portable.Licensing.Security.Cryptography
{
    public class NativeKeyGenerator : KeyGenerator
    {
        public override KeyPair GenerateKeyPair()
        {
            // Create a new key pair using ECDsa
            try
            {
                // Try ECDsa first (the original implementation)
                return new NativeKeyPair(ECDsa.Create());
            }
            catch (CryptographicException)
            {
                // If ECDsa fails, fall back to RSA
                return new NativeKeyPair(RSA.Create(2048)); // 2048-bit key is standard
            }
        }
    }
}
#endif