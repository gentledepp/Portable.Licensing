#if NET9_0_OR_GREATER

using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Portable.Licensing.Security.Cryptography
{
    /// <summary>
    /// Converts public keys between BouncyCastle and .NET native formats.
    /// Used to ensure compatibility between BouncySigner and NativeSigner.
    /// </summary>
    public static class BouncyNativeConverter
    {
        /// <summary>
        /// Converts a BouncyCastle public key to .NET native format for use with NativeSigner.
        /// </summary>
        /// <param name="bouncyPublicKey">The public key in Base64 format as created by BouncySigner</param>
        /// <returns>A Base64 encoded key in SubjectPublicKeyInfo format compatible with NativeSigner</returns>
        public static string ConvertToNativeFormat(string bouncyPublicKey)
        {
            if (string.IsNullOrEmpty(bouncyPublicKey))
                throw new ArgumentNullException(nameof(bouncyPublicKey), "Public key cannot be null or empty");

            try
            {
                // Decode the Base64 string to get the raw key bytes
                byte[] keyData = Convert.FromBase64String(bouncyPublicKey);

                // Parse using BouncyCastle's PublicKeyFactory
                AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(keyData);

                // Convert to SubjectPublicKeyInfo format
                SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(asymmetricKeyParameter);
                byte[] spkiBytes = spki.GetEncoded();

                // Encode as Base64 string
                return Convert.ToBase64String(spkiBytes);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Failed to convert public key format", ex);
            }
        }

        /// <summary>
        /// Verifies if a key is compatible with NativeSigner without conversion.
        /// </summary>
        /// <param name="publicKey">The public key in Base64 format</param>
        /// <returns>True if the key is compatible with NativeSigner, false otherwise</returns>
        public static bool IsNativeCompatible(string publicKey)
        {
            if (string.IsNullOrEmpty(publicKey))
                return false;

            try
            {
                byte[] keyData = Convert.FromBase64String(publicKey);

                // Try to load as ECDsa key
                try
                {
                    using var ecdsa = ECDsa.Create();
                    ecdsa.ImportSubjectPublicKeyInfo(keyData, out _);
                    return true;
                }
                catch
                {
                    // Not an EC key, try RSA
                }

                // Try to load as RSA key
                try
                {
                    using var rsa = RSA.Create();
                    rsa.ImportSubjectPublicKeyInfo(keyData, out _);
                    return true;
                }
                catch
                {
                    // Not an RSA key either
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Provides information about the public key type and parameters.
        /// </summary>
        /// <param name="publicKey">The public key in Base64 format</param>
        /// <returns>A string with information about the key</returns>
        public static string GetKeyInfo(string publicKey)
        {
            if (string.IsNullOrEmpty(publicKey))
                return "Empty key";

            try
            {
                byte[] keyData = Convert.FromBase64String(publicKey);
                AsymmetricKeyParameter key = PublicKeyFactory.CreateKey(keyData);

                if (key is ECPublicKeyParameters ecKey)
                {
                    return $"EC Key: Curve={ecKey.Parameters.Curve.FieldSize} bits" +
                           $", Q=({ecKey.Q.AffineXCoord.ToBigInteger().ToString(16).Substring(0, 8)}..., " +
                           $"{ecKey.Q.AffineYCoord.ToBigInteger().ToString(16).Substring(0, 8)}...)";
                }
                else if (key is RsaKeyParameters rsaKey)
                {
                    return $"RSA Key: Modulus={rsaKey.Modulus.BitLength} bits" +
                           $", Exponent={rsaKey.Exponent}";
                }
                else if (key is DsaPublicKeyParameters dsaKey)
                {
                    return $"DSA Key: P={dsaKey.Parameters.P.BitLength} bits";
                }
                else
                {
                    return $"Unknown key type: {key.GetType().Name}";
                }
            }
            catch (Exception ex)
            {
                return $"Error analyzing key: {ex.Message}";
            }
        }

        /// <summary>
        /// Attempts to restore the original key from various formats by trying multiple approaches.
        /// </summary>
        /// <param name="publicKey">The public key in any supported format</param>
        /// <returns>Both the original and SPKI formats of the key</returns>
        public static (string OriginalFormat, string SpkiFormat) NormalizeKey(string publicKey)
        {
            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentNullException(nameof(publicKey));

            try
            {
                byte[] keyData = Convert.FromBase64String(publicKey);

                // Parse the key with BouncyCastle
                AsymmetricKeyParameter key = PublicKeyFactory.CreateKey(keyData);

                // Get the SPKI format
                SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key);
                string spkiFormat = Convert.ToBase64String(spki.GetEncoded());

                // For the original format, we need to extract just the key data without ASN.1 wrapping
                string originalFormat;

                if (key is ECPublicKeyParameters)
                {
                    // For EC, we'd typically want the raw point data
                    DerBitString bitString = spki.PublicKeyData;
                    originalFormat = Convert.ToBase64String(bitString.GetBytes());
                }
                else if (key is RsaKeyParameters)
                {
// Or if that doesn't work, just use the SubjectPublicKeyInfo format for RSA keys too:
                    originalFormat = spkiFormat;
                }
                else
                {
                    // For other key types, just use the SPKI format
                    originalFormat = spkiFormat;
                }

                return (originalFormat, spkiFormat);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Failed to normalize key format", ex);
            }
        }
    }
}
#endif