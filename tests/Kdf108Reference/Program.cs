using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using MicroCard.Framework;

var host = new ReferenceHost(Convert.FromHexString("404142434445464748494A4B4C4D4E4F"));
Host.Current = host;
Kdf108Consumer.Install();
host.Command = Convert.FromHexString("04080102030405060708");
Kdf108Consumer.Process();
var expected = Convert.FromHexString("36A53A0E1D4183458EF52AB845E5DDC2");
if (host.StatusWord != 0x9000 || !host.Response.SequenceEqual(expected))
    throw new Exception($"KDF mismatch: {Convert.ToHexString(host.Response)}");
if (host.CmacCalls != 1 || !host.LastCmacInput.SequenceEqual(
        Convert.FromHexString("000000000000000000000004000080010102030405060708")))
    throw new Exception("SCP03 fixed-input layout or native CMAC boundary mismatch");
if (!host.OpenedOpaqueKey || host.ExposedKey)
    throw new Exception("The entry must use an opaque SSD-owned key handle");
Console.WriteLine("PASS: SCP03 SP800-108 AES-CMAC, opaque key handle and APDU boundary");

sealed class ReferenceHost(byte[] key) : IHost
{
    static readonly byte[] Token = Convert.FromHexString("4D434B48000000010000000100000001");
    public byte[] Command { get; set; } = [];
    public List<byte> ResponseBytes { get; } = [];
    public byte[] Response => ResponseBytes.ToArray();
    public int StatusWord { get; private set; } = 0x9000;
    public int CmacCalls { get; private set; }
    public byte[] LastCmacInput { get; private set; } = [];
    public bool OpenedOpaqueKey { get; private set; }
    public bool ExposedKey => false;
    public int CommandLength => Command.Length;
    public void CopyCommandTo(byte[] destination, int destinationOffset, int sourceOffset, int length) =>
        Array.Copy(Command, sourceOffset, destination, destinationOffset, length);
    public void WriteResponse(byte[] source, int sourceOffset, int length)
    {
        for (int index = 0; index < length; index++) ResponseBytes.Add(source[sourceOffset + index]);
    }
    public void Status(int value) => StatusWord = value;
    public byte[] GenerateKey(int slot, int algorithm) => slot == 2 && algorithm == KeyAlgorithms.Aes128 ? Token : throw new Exception();
    public byte[] OpenKey(int slot) { if (slot != 2) throw new Exception(); OpenedOpaqueKey = true; return Token; }
    public byte[] KeyOperation(int operation, byte[] token, byte[][] data)
    {
        if (operation != 26 || !token.SequenceEqual(Token) || data.Length != 1) throw new Exception("Invalid native CMAC call");
        CmacCalls++; LastCmacInput = data[0].ToArray();
        return Cmac(key, data[0]);
    }
    public byte[] KeyOperation(int operation, byte[] token, byte[] data, int offset, int length) =>
        throw new NotSupportedException();

    public bool P256Verify(byte[] publicKey, byte[] data, byte[] signature) => false;
    public void CreateCredential(int slot, byte[] pin, int pinOffset, int pinLength, int pinRetries,
        byte[] puk, int pukOffset, int pukLength, int pukRetries) => throw new NotSupportedException();
    public bool VerifyCredential(int slot, byte[] candidate, int offset, int length) => false;
    public bool IsCredentialVerified(int slot) => false;
    public void ChangeCredential(int slot, byte[] newPin, int offset, int length) =>
        throw new NotSupportedException();
    public bool UnblockCredential(int slot, byte[] puk, int pukOffset, int pukLength, byte[] newPin,
        int newPinOffset, int newPinLength) => false;
    public int CredentialRetries(int slot, int kind) => 0;
    public void DeleteKey(int slot) => throw new NotSupportedException();
    public int Get(int key) => 0;
    public void Set(int key, int value) { }
    public byte[] GetBytes(int key) => [];
    public void SetBytes(int key, byte[] value) { }
    public void SetBytes(int key, byte[] value, int offset, int length) { }
    public void DeleteBytes(int key) { }
    public bool ContainsBytes(int key) => false;
    public void BeginTransaction() { }
    public void CommitTransaction() { }
    public void AbortTransaction() { }
    public int Random() => 0;
    public void FillRandom(byte[] destination, int offset, int length) =>
        Array.Clear(destination, offset, length);
    public int SecurityLevel => 0;
    public void Gpio(int resource, int value) { }

    static byte[] Cmac(byte[] key, byte[] input)
    {
        var zero = new byte[16];
        var firstSubkey = Double(Encrypt(key, zero));
        var secondSubkey = Double(firstSubkey);
        int blocks = input.Length == 0 ? 1 : (input.Length + 15) / 16;
        bool complete = input.Length != 0 && input.Length % 16 == 0;
        var state = new byte[16];
        for (int block = 0; block < blocks - 1; block++)
        {
            for (int index = 0; index < 16; index++) state[index] ^= input[block * 16 + index];
            state = Encrypt(key, state);
        }
        var last = new byte[16];
        int remaining = input.Length - (blocks - 1) * 16;
        for (int index = 0; index < remaining; index++) last[index] = input[(blocks - 1) * 16 + index];
        if (!complete) last[remaining] = 0x80;
        var subkey = complete ? firstSubkey : secondSubkey;
        for (int index = 0; index < 16; index++) state[index] ^= (byte)(last[index] ^ subkey[index]);
        return Encrypt(key, state);
    }

    static byte[] Double(byte[] value)
    {
        var result = new byte[16];
        int carry = 0;
        for (int index = 15; index >= 0; index--)
        {
            int next = value[index]; result[index] = (byte)((next << 1) | carry); carry = next >> 7;
        }
        if (carry != 0) result[15] ^= 0x87;
        return result;
    }

    static byte[] Encrypt(byte[] key, byte[] block)
    {
        using var aes = Aes.Create();
        aes.Key = key; aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None;
        return aes.CreateEncryptor().TransformFinalBlock(block, 0, block.Length);
    }
}
