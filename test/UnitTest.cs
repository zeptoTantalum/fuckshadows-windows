using System;
using Fuckshadows.Controller;
using Fuckshadows.Encryption;
using Fuckshadows.Encryption.Stream;
using GlobalHotKey;
using System.Windows.Input;
using System.Threading;
using System.Collections.Generic;
using System.Text;
using Fuckshadows.Controller.Hotkeys;
using Fuckshadows.Encryption.AEAD;
using NUnit.Framework;

namespace test
{
    [TestFixture]
    public class UnitTest
    {
        private void RunStreamEncryptionRound(IEncryptor encryptor, IEncryptor decryptor)
        {
            RNG.Reload();
            byte[] plain = new byte[16384];
            const int IV = 16;
            byte[] cipher = new byte[plain.Length + IV];
            byte[] plain2 = new byte[plain.Length + IV];
            int outLen = 0;
            int outLen2 = 0;

            _random.NextBytes(plain);
            encryptor.Encrypt(plain, plain.Length, cipher, out outLen);
            decryptor.Decrypt(cipher, outLen, plain2, out outLen2);
            Assert.AreEqual(plain.Length, outLen2);
            for (int j = 0; j < plain.Length; j++)
            {
                Assert.AreEqual(plain[j], plain2[j]);
            }
            encryptor.Encrypt(plain, 1000, cipher, out outLen);
            decryptor.Decrypt(cipher, outLen, plain2, out outLen2);
            Assert.AreEqual(1000, outLen2);
            for (int j = 0; j < outLen2; j++)
            {
                Assert.AreEqual(plain[j], plain2[j]);
            }
            encryptor.Encrypt(plain, 12333, cipher, out outLen);
            decryptor.Decrypt(cipher, outLen, plain2, out outLen2);
            Assert.AreEqual(12333, outLen2);
            for (int j = 0; j < outLen2; j++)
            {
                Assert.AreEqual(plain[j], plain2[j]);
            }
        }

        private void RunAEADEncryptionRound(IEncryptor encryptor, IEncryptor decryptor)
        {
            RNG.Reload();
            byte[] plain = new byte[16384];
            const int Salt = 16;
            // make the cipher array large enough to hold chunks
            byte[] cipher = new byte[plain.Length * 4 + Salt];
            byte[] plain2 = new byte[plain.Length + Salt];
            int outLen = 0;
            int outLen2 = 0;

            _random.NextBytes(plain);
            encryptor.Encrypt(plain, plain.Length, cipher, out outLen);
            decryptor.Decrypt(cipher, outLen, plain2, out outLen2);
            Assert.AreEqual(plain.Length, outLen2);
            for (int j = 0; j < plain.Length; j++)
            {
                Assert.AreEqual(plain[j], plain2[j]);
            }
            encryptor.Encrypt(plain, 1000, cipher, out outLen);
            decryptor.Decrypt(cipher, outLen, plain2, out outLen2);
            Assert.AreEqual(1000, outLen2);
            for (int j = 0; j < outLen2; j++)
            {
                Assert.AreEqual(plain[j], plain2[j]);
            }
            encryptor.Encrypt(plain, 12333, cipher, out outLen);
            decryptor.Decrypt(cipher, outLen, plain2, out outLen2);
            Assert.AreEqual(12333, outLen2);
            for (int j = 0; j < outLen2; j++)
            {
                Assert.AreEqual(plain[j], plain2[j]);
            }
        }

        private static bool encryptionFailed = false;
        private Random _random = new Random();

        [TestCase]
        public void TestCompareVersion()
        {
            Assert.IsTrue(UpdateChecker.Asset.CompareVersion("2.3.1.0", "2.3.1") == 0);
            Assert.IsTrue(UpdateChecker.Asset.CompareVersion("1.2", "1.3") < 0);
            Assert.IsTrue(UpdateChecker.Asset.CompareVersion("1.3", "1.2") > 0);
            Assert.IsTrue(UpdateChecker.Asset.CompareVersion("1.3", "1.3") == 0);
            Assert.IsTrue(UpdateChecker.Asset.CompareVersion("1.2.1", "1.2") > 0);
            Assert.IsTrue(UpdateChecker.Asset.CompareVersion("2.3.1", "2.4") < 0);
            Assert.IsTrue(UpdateChecker.Asset.CompareVersion("1.3.2", "1.3.1") > 0);
        }

        [TestCase]
        public void TestHotKey2Str()
        {
            Assert.AreEqual("Ctrl+A", HotKeys.HotKey2Str(Key.A, ModifierKeys.Control));
            Assert.AreEqual("Ctrl+Alt+D2", HotKeys.HotKey2Str(Key.D2, (ModifierKeys.Alt | ModifierKeys.Control)));
            Assert.AreEqual("Ctrl+Alt+Shift+NumPad7",
                HotKeys.HotKey2Str(Key.NumPad7, (ModifierKeys.Alt | ModifierKeys.Control | ModifierKeys.Shift)));
            Assert.AreEqual("Ctrl+Alt+Shift+F6",
                HotKeys.HotKey2Str(Key.F6, (ModifierKeys.Alt | ModifierKeys.Control | ModifierKeys.Shift)));
            Assert.AreNotEqual("Ctrl+Shift+Alt+F6",
                HotKeys.HotKey2Str(Key.F6, (ModifierKeys.Alt | ModifierKeys.Control | ModifierKeys.Shift)));
        }

        [TestCase]
        public void TestStr2HotKey()
        {
            Assert.IsTrue(HotKeys.Str2HotKey("Ctrl+A").Equals(new HotKey(Key.A, ModifierKeys.Control)));
            Assert.IsTrue(
                HotKeys.Str2HotKey("Ctrl+Alt+A").Equals(new HotKey(Key.A, (ModifierKeys.Control | ModifierKeys.Alt))));
            Assert.IsTrue(
                HotKeys.Str2HotKey("Ctrl+Shift+A")
                    .Equals(new HotKey(Key.A, (ModifierKeys.Control | ModifierKeys.Shift))));
            Assert.IsTrue(
                HotKeys.Str2HotKey("Ctrl+Alt+Shift+A")
                    .Equals(new HotKey(Key.A, (ModifierKeys.Control | ModifierKeys.Alt | ModifierKeys.Shift))));
            HotKey testKey0 = HotKeys.Str2HotKey("Ctrl+Alt+Shift+A");
            Assert.IsTrue(testKey0 != null &&
                          testKey0.Equals(new HotKey(Key.A,
                              (ModifierKeys.Control | ModifierKeys.Alt | ModifierKeys.Shift))));
            HotKey testKey1 = HotKeys.Str2HotKey("Ctrl+Alt+Shift+F2");
            Assert.IsTrue(testKey1 != null &&
                          testKey1.Equals(new HotKey(Key.F2,
                              (ModifierKeys.Control | ModifierKeys.Alt | ModifierKeys.Shift))));
            HotKey testKey2 = HotKeys.Str2HotKey("Ctrl+Shift+Alt+D7");
            Assert.IsTrue(testKey2 != null &&
                          testKey2.Equals(new HotKey(Key.D7,
                              (ModifierKeys.Control | ModifierKeys.Alt | ModifierKeys.Shift))));
            HotKey testKey3 = HotKeys.Str2HotKey("Ctrl+Shift+Alt+NumPad7");
            Assert.IsTrue(testKey3 != null &&
                          testKey3.Equals(new HotKey(Key.NumPad7,
                              (ModifierKeys.Control | ModifierKeys.Alt | ModifierKeys.Shift))));
        }

        [TestCase]
        public void TestMD5()
        {
            for (int len = 1; len < 64; len++)
            {
                System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create();
                byte[] bytes = new byte[len];
                _random.NextBytes(bytes);
                string md5str = Convert.ToBase64String(md5.ComputeHash(bytes));
                string md5str2 = Convert.ToBase64String(MbedTLS.MD5(bytes));
                Assert.IsTrue(md5str == md5str2);
            }
        }

        [TestCase]
        public void TestMbedTLSEncryption()
        {
            // run it once before the multi-threading test to initialize global tables
            RunSingleMbedTLSEncryptionThread();
            List<Thread> threads = new List<Thread>();
            for (int i = 0; i < 10; i++)
            {
                Thread t = new Thread(RunSingleMbedTLSEncryptionThread);
                threads.Add(t);
                t.Start();
            }
            foreach (Thread t in threads)
            {
                t.Join();
            }
            RNG.Close();
            Assert.IsFalse(encryptionFailed);
        }

        private void RunSingleMbedTLSEncryptionThread()
        {
            try
            {
                for (int i = 0; i < 100; i++)
                {
                    IEncryptor encryptor = new StreamMbedTLSEncryptor("aes-256-cfb", "barfoo!");
                    IEncryptor decryptor = new StreamMbedTLSEncryptor("aes-256-cfb", "barfoo!");
                    RunStreamEncryptionRound(encryptor, decryptor);
                }
//                for (int i = 0; i < 100; i++) {
//                    IEncryptor encryptor = new AEADMbedTLSEncryptor("aes-256-gcm", "barfoo!");
//                    IEncryptor decryptor = new AEADMbedTLSEncryptor("aes-256-gcm", "barfoo!");
//                    RunAEADEncryptionRound(encryptor, decryptor);
//                }
            }
            catch
            {
                encryptionFailed = true;
                throw;
            }
        }

        [TestCase]
        public void TestRC4Encryption()
        {
            // run it once before the multi-threading test to initialize global tables
            RunSingleRC4EncryptionThread();
            List<Thread> threads = new List<Thread>();
            for (int i = 0; i < 10; i++)
            {
                Thread t = new Thread(RunSingleRC4EncryptionThread);
                threads.Add(t);
                t.Start();
            }
            foreach (Thread t in threads)
            {
                t.Join();
            }
            RNG.Close();
            Assert.IsFalse(encryptionFailed);
        }

        private void RunSingleRC4EncryptionThread()
        {
            try
            {
                for (int i = 0; i < 100; i++)
                {
                    IEncryptor encryptor = new StreamMbedTLSEncryptor("rc4-md5", "barfoo!");
                    IEncryptor decryptor = new StreamMbedTLSEncryptor("rc4-md5", "barfoo!");
                    RunStreamEncryptionRound(encryptor, decryptor);
                }
            }
            catch
            {
                encryptionFailed = true;
                throw;
            }
        }

        [TestCase]
        public void TestSodiumEncryption()
        {
            // run it once before the multi-threading test to initialize global tables
            RunSingleSodiumEncryptionThread();
            List<Thread> threads = new List<Thread>();
            for (int i = 0; i < 10; i++)
            {
                Thread t = new Thread(RunSingleSodiumEncryptionThread);
                threads.Add(t);
                t.Start();
            }
            foreach (Thread t in threads)
            {
                t.Join();
            }
            RNG.Close();
            Assert.IsFalse(encryptionFailed);
        }

        private void RunSingleSodiumEncryptionThread()
        {
            try
            {
                for (int i = 0; i < 100; i++)
                {
                    IEncryptor encryptor = new StreamSodiumEncryptor("salsa20", "barfoo!");
                    IEncryptor decryptor = new StreamSodiumEncryptor("salsa20", "barfoo!");
                    RunStreamEncryptionRound(encryptor, decryptor);
                }
//                for (int i = 0; i < 100; i++)
//                {
//                    IEncryptor encryptor = new AEADSodiumEncryptor("chacha20-ietf-poly1305", "barfoo!");
//                    IEncryptor decryptor = new AEADSodiumEncryptor("chacha20-ietf-poly1305", "barfoo!");
//                    RunAEADEncryptionRound(encryptor, decryptor);
//                }
            }
            catch
            {
                encryptionFailed = true;
                throw;
            }
        }

        [TestCase]
        public void TestLegacyDeriveKey() {
            string pass = "test-legacy";
            byte[] passBytes = Encoding.UTF8.GetBytes(pass);
            byte[] key1 = new byte[32];
            StreamEncryptor.LegacyDeriveKey(passBytes, key1);
            byte[] key2 = { 0x7b, 0x14, 0xff, 0x93, 0xd6, 0x63, 0x27, 0xfa, 0xd4, 0xdc, 0x37, 0x86, 0x46, 0x86, 0x3f, 0xc4, 0x53, 0x04, 0xd0, 0xdb, 0xf3, 0x79, 0xbd, 0xb5, 0x54, 0x44, 0xf9, 0x91, 0x80, 0x50, 0x7e, 0xa2 };
            string key1str = Convert.ToBase64String(key1);
            string key2str = Convert.ToBase64String(key2);
            Assert.IsTrue(key1str == key2str);
        }

        [TestCase]
        public void TestDeriveKey()
        {
            string pass = "test-aead-derive-key";
            byte[] passBytes = Encoding.UTF8.GetBytes(pass);
            byte[] key1 = new byte[32];
            AEADSodiumEncryptor encryptor = new AEADSodiumEncryptor("chacha20-ietf-poly1305", pass);
            encryptor.DeriveKey(passBytes, key1);
            byte[] key2 = { 0xb5, 0x02, 0xe1, 0x43, 0x31, 0x6e, 0xea, 0xad, 0x3d, 0x9d, 0xd2, 0x9f, 0x1c, 0xdc, 0x1a, 0xe9, 0xbd, 0x48, 0x2c, 0xda, 0xa8, 0x21, 0x99, 0x3b, 0x85, 0x45, 0x22, 0x34, 0x9a, 0x91, 0x33, 0xfd };
            string key1str = Convert.ToBase64String(key1);
            string key2str = Convert.ToBase64String(key2);
            Assert.IsTrue(key1str == key2str);
        }

        [TestCase]
        public void TestDeriveSessionKey() {
            string pass = "test-aead-derive-session-key";
            byte[] skey1 = new byte[32];
            byte[] saltBytes = { 0x8c, 0xfe, 0x67, 0x9a, 0x4c, 0x05, 0xfe, 0x36, 0xca, 0x00, 0x9c, 0x90, 0xe9, 0x66, 0x5b, 0x48, 0x35, 0x1c, 0x07, 0x55, 0x18, 0x94, 0x32, 0x72, 0xc8, 0x40, 0xd2, 0xfd, 0x1f, 0xd4, 0xf1, 0x22 };
            byte[] masterKeyBytes = { 0x4d, 0x79, 0xd4, 0x6e, 0x63, 0x7d, 0xb5, 0x0d, 0xd1, 0x7b, 0x24, 0xe3, 0xb8, 0xdf, 0xf3, 0xb5, 0xde, 0xba, 0x42, 0xaf, 0x3a, 0x2e, 0x94, 0xbf, 0xb2, 0xf4, 0x37, 0x91, 0xae, 0xd4, 0x65, 0x04 };
            byte[] skey2 = { 0x60, 0xc7, 0xa8, 0xe5, 0x59, 0x6b, 0x7a, 0xcd, 0x65, 0xd8, 0xe5, 0x54, 0x31, 0x57, 0x89, 0xf2, 0x39, 0xa7, 0xf8, 0x96, 0x37, 0x88, 0x90, 0x9e, 0xc1, 0xe1, 0xc2, 0xb7, 0xf0, 0x9f, 0x6f, 0xd9 };
            AEADSodiumEncryptor encryptor = new AEADSodiumEncryptor("chacha20-ietf-poly1305", pass);
            encryptor.DeriveSessionKey(saltBytes, masterKeyBytes, skey1);
            string skey1str = Convert.ToBase64String(skey1);
            string skey2str = Convert.ToBase64String(skey2);
            Assert.IsTrue(skey1str == skey2str);
        }
    }
}