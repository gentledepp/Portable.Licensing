#if NET5_0_OR_GREATER
using System;
using System.Security.Cryptography;

namespace Portable.Licensing.Security.Cryptography
{
    public class NativeKeyPair : KeyPair
    {
        private readonly AsymmetricAlgorithm algorithm;

        public NativeKeyPair(AsymmetricAlgorithm algorithm)
        {
            this.algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
        }

        /// <summary>
        /// Gets the encrypted and DER encoded private key.
        /// </summary>
        /// <param name="passPhrase">The pass phrase to encrypt the private key.</param>
        /// <returns>The encrypted private key.</returns>
        public override string ToEncryptedPrivateKeyString(string passPhrase)
        {
            try
            {
                // Try standard PKCS8 export with triple DES encryption
                var data = this.algorithm.ExportEncryptedPkcs8PrivateKey(
                    passPhrase, 
                    new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 10)
                );
                return Convert.ToBase64String(data);
            }
            catch (CryptographicException ex)
            {
                // If triple DES fails, try with AES
                try
                {
                    var data = this.algorithm.ExportEncryptedPkcs8PrivateKey(
                        passPhrase,
                        new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 10)
                    );
                    return Convert.ToBase64String(data);
                }
                catch
                {
                    // Re-throw the original exception if alternative encryption fails
                    throw ex;
                }
            }
        }

        /// <summary>
        /// Gets the DER encoded public key.
        /// </summary>
        /// <returns>The public key.</returns>
        public override string ToPublicKeyString()
        {
            var data = this.algorithm.ExportSubjectPublicKeyInfo();
            return Convert.ToBase64String(data);
        }
    }
}
#endif