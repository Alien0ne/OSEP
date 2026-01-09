using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace AESShellcodeEncryptor
{
    class Program
    {
        // Constants
        const uint PROV_RSA_AES = 24;
        const uint CALG_AES_256 = 0x00006610;
        const uint CALG_SHA_256 = 0x0000800C;
        const uint CRYPT_VERIFYCONTEXT = 0xF0000000;

        // Win32 API imports
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CryptAcquireContext(ref IntPtr hProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CryptCreateHash(IntPtr hProv, uint Algid, IntPtr hKey, uint dwFlags, ref IntPtr phHash);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CryptHashData(IntPtr hHash, byte[] pbData, int dataLen, uint flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CryptDeriveKey(IntPtr hProv, uint Algid, IntPtr hBaseData, uint flags, ref IntPtr phKey);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CryptEncrypt(IntPtr hKey, IntPtr hHash, bool Final, uint dwFlags, byte[] pbData, ref int pdwDataLen, int bufLen);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CryptDestroyKey(IntPtr hKey);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CryptDestroyHash(IntPtr hHash);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CryptReleaseContext(IntPtr hProv, uint dwFlags);

        static void Main(string[] args)
        {
            string inputFile = "shellcode.bin";
            string outputFile = "payload.txt";

            if (!File.Exists(inputFile))
            {
                Console.WriteLine("[-] shellcode.bin not found.");
                return;
            }

            byte[] shellcode = File.ReadAllBytes(inputFile);
            Console.WriteLine($"[*] Read {shellcode.Length} bytes from shellcode.bin");

            // Generate 256-bit key material
            byte[] keyMaterial = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(keyMaterial);
            }

            byte[] encrypted = EncryptCryptoAPI(shellcode, keyMaterial);

            string b64Key = Convert.ToBase64String(keyMaterial);
            string b64Encrypted = Convert.ToBase64String(encrypted);

            File.WriteAllText(outputFile,
                "=== AES Key (Base64) ===\n" +
                b64Key + "\n\n" +
                "=== Encrypted Shellcode (Base64) ===\n" +
                b64Encrypted + "\n");

            Console.WriteLine("[+] Encryption complete.");
            Console.WriteLine($"[+] Output saved to: {outputFile}");
        }

        static byte[] EncryptCryptoAPI(byte[] data, byte[] keyMaterial)
        {
            IntPtr hProv = IntPtr.Zero;
            IntPtr hHash = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;

            try
            {
                if (!CryptAcquireContext(ref hProv, null, null, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
                    throw new Exception("CryptAcquireContext failed");

                if (!CryptCreateHash(hProv, CALG_SHA_256, IntPtr.Zero, 0, ref hHash))
                    throw new Exception("CryptCreateHash failed");

                if (!CryptHashData(hHash, keyMaterial, keyMaterial.Length, 0))
                    throw new Exception("CryptHashData failed");

                if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, ref hKey))
                    throw new Exception("CryptDeriveKey failed");

                int dataLen = data.Length;
                int bufLen = dataLen + 32; // Padding
                byte[] buffer = new byte[bufLen];
                Buffer.BlockCopy(data, 0, buffer, 0, dataLen);

                if (!CryptEncrypt(hKey, IntPtr.Zero, true, 0, buffer, ref dataLen, bufLen))
                    throw new Exception("CryptEncrypt failed");

                byte[] result = new byte[dataLen];
                Array.Copy(buffer, result, dataLen);
                return result;
            }
            finally
            {
                if (hKey != IntPtr.Zero) CryptDestroyKey(hKey);
                if (hHash != IntPtr.Zero) CryptDestroyHash(hHash);
                if (hProv != IntPtr.Zero) CryptReleaseContext(hProv, 0);
            }
        }
    }
}
