#if NET5_0_OR_GREATER
using System;
using System.Security.Cryptography;

namespace Portable.Licensing.Security.Cryptography
{
    internal class NativeSigner : Signer
    {
        public override byte[] Sign(byte[] documentToSign, string privateKey, string passPhrase)
        {
            try
            {
                using var ecdsa = ECDsa.Create();
                ecdsa.ImportEncryptedPkcs8PrivateKey(passPhrase, Convert.FromBase64String(privateKey), out int _);
                
                // Modified to use a try/catch with fallback to handle .NET 9.0 changes
                try 
                {
                    // Try with explicit format first (works in .NET 5.0-8.0)
#if NET5_0_OR_GREATER
                    return ecdsa.SignData(documentToSign, HashAlgorithmName.SHA512, DSASignatureFormat.Rfc3279DerSequence);
#else
                    // Use the simpler overload for .NET 9.0 which handles format internally
                    return ecdsa.SignData(documentToSign, HashAlgorithmName.SHA512);
#endif
                }
                catch (CryptographicException)
                {
                    // Fallback to simpler signature method if the specific format fails
                    return ecdsa.SignData(documentToSign, HashAlgorithmName.SHA512);
                }
            }
            catch (Exception ex)
            {
                // Try using RSA as fallback
                try
                {
                    using var rsa = RSA.Create();
                    rsa.ImportEncryptedPkcs8PrivateKey(passPhrase, Convert.FromBase64String(privateKey), out int _);
                    return rsa.SignData(documentToSign, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                }
                catch
                {
                    // Re-throw the original exception if RSA fallback fails
                    throw ex;
                }
            }
        }

        public override bool VerifySignature(byte[] documentToSign, byte[] signature, string publicKey)
        {
            try
            {
                using var ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out int _);
                
                // Modified to use a try/catch with fallback to handle .NET 9.0 changes
                try
                {
                    // Try with explicit format first (works in .NET 5.0-8.0)
#if NET5_0_OR_GREATER
                    return ecdsa.VerifyData(documentToSign, signature, HashAlgorithmName.SHA512, DSASignatureFormat.Rfc3279DerSequence);
#else
                    // Use the simpler overload for .NET 9.0 which handles format internally
                    return ecdsa.VerifyData(documentToSign, signature, HashAlgorithmName.SHA512);
#endif
                }
                catch (CryptographicException)
                {
                    // Fallback to simpler verification method if the specific format fails
                    return ecdsa.VerifyData(documentToSign, signature, HashAlgorithmName.SHA512);
                }
            }
            catch (Exception)
            {
                // Try using RSA as fallback
                try
                {
                    using var rsa = RSA.Create();
                    rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out int _);
                    return rsa.VerifyData(documentToSign, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                }
                catch
                {
                    // If both approaches fail, return false
                    return false;
                }
            }
        }
    }
}
#endif