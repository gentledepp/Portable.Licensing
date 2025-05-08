namespace Portable.Licensing.Security.Cryptography
{
    public abstract class KeyGenerator
    {
        public static KeyGenerator Create()
        {
#if NET452 || NETSTANDARD2_0 || IOS
            return new BouncyKeyGenerator();
#else
            return new NativeKeyGenerator();
#endif
        }

        /// <summary>
        /// Generates a private/public key pair for license signing.
        /// </summary>
        /// <returns>A KeyPair containing the keys.</returns>
        public abstract KeyPair GenerateKeyPair();
    }
}