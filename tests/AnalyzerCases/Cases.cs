using MicroCard.Framework;
using System.Transactions;

[assembly: Dependency("mscorlib", "1.2.x", SignerPublicKeyHex = "0000000000000000000000000000000000000000000000000000000000000000")]
[assembly: PersistentInt32(1)]

#if CASE_STORAGE_SCHEMA
[assembly: PersistentBytes(1, 0)]
#endif

#if CASE_EXPORT
[assembly: DependencyExport("00")]
#else
[assembly: DependencyExport(DependencyAccess.Any)]
#endif

#if CASE_DEPENDENCY
[assembly: Dependency("Provider", "1..2")]
#endif

#if CASE_DEPENDENCY_LIMIT
[assembly: Dependency("D00", "=1.0.0")]
[assembly: Dependency("D01", "=1.0.0")]
[assembly: Dependency("D02", "=1.0.0")]
[assembly: Dependency("D03", "=1.0.0")]
[assembly: Dependency("D04", "=1.0.0")]
[assembly: Dependency("D05", "=1.0.0")]
[assembly: Dependency("D06", "=1.0.0")]
[assembly: Dependency("D07", "=1.0.0")]
[assembly: Dependency("D08", "=1.0.0")]
[assembly: Dependency("D09", "=1.0.0")]
[assembly: Dependency("D10", "=1.0.0")]
[assembly: Dependency("D11", "=1.0.0")]
[assembly: Dependency("D12", "=1.0.0")]
[assembly: Dependency("D13", "=1.0.0")]
[assembly: Dependency("D14", "=1.0.0")]
[assembly: Dependency("D15", "=1.0.0")]
#endif

#if CASE_DEPENDENCY_BOUNDARY
[assembly: Dependency("D00", "=1.0.0")]
[assembly: Dependency("D01", "=1.0.0")]
[assembly: Dependency("D02", "=1.0.0")]
[assembly: Dependency("D03", "=1.0.0")]
[assembly: Dependency("D04", "=1.0.0")]
[assembly: Dependency("D05", "=1.0.0")]
[assembly: Dependency("D06", "=1.0.0")]
[assembly: Dependency("D07", "=1.0.0")]
[assembly: Dependency("D08", "=1.0.0")]
[assembly: Dependency("D09", "=1.0.0")]
[assembly: Dependency("D10", "=1.0.0")]
[assembly: Dependency("D11", "=1.0.0")]
[assembly: Dependency("D12", "=1.0.0")]
[assembly: Dependency("D13", "=1.0.0")]
[assembly: Dependency("D14", "=1.0.0")]
#endif

#if CASE_REFERENCE_ALIAS
[assembly: Dependency("Provider", "=1.0.0", ReferenceAssembly = "SharedReference")]
[assembly: Dependency("Provider2", "=1.0.0", ReferenceAssembly = "SharedReference")]
#endif

#if CASE_REFERENCE_RESERVED
[assembly: Dependency("Provider", "=1.0.0", ReferenceAssembly = "MicroCard.Framework")]
#endif

#if CASE_DEVICE_IDENTITY
[assembly: DeviceAssemblyIdentity("System.Runtime")]
#endif

#if CASE_IDENTIFIER
[assembly: DeviceAssemblyIdentity("bad/name")]
#endif

namespace MicroCard.AnalyzerCases;

[Assembly("F04D430020")]
public static class ValidAssembly
{
    [Process]
    public static void Process()
    {
        int value = SecurityDomain.Current.Store.GetInt32(1);
        byte[] response = [(byte)value];
        ResponseApdu.Write(response, 0, response.Length);
    }
}

#if CASE_TRANSACTION_SCOPE
public static class ValidTransactionScope
{
    public static void Run() => Commit();

    private static void Commit()
    {
        using var scope = new TransactionScope();
        SecurityDomain.Current.Store.SetInt32(1, 1);
        scope.Complete();
    }

    public static void Abort()
    {
        using var scope = new TransactionScope();
        SecurityDomain.Current.Store.SetInt32(1, 2);
    }
}
#endif

#if CASE_TRANSACTION_CURRENT
public static class InvalidAmbientTransaction
{
    public static void Run() { _ = Transaction.Current; }
}
#endif

#if CASE_TRANSACTION_LIFECYCLE
[Assembly("F04D430022")]
public static class InvalidLifecycleTransaction
{
    [Install]
    public static void Install()
    {
        using var scope = new TransactionScope();
        scope.Complete();
    }

    [Process]
    public static void Process() { }
}
#endif

#if CASE_STORAGE_ACCESS
public static class InvalidStorageAccess
{
    public static int DynamicKey(int key) => SecurityDomain.Current.Store.GetInt32(key);
    public static byte[] WrongKind() => SecurityDomain.Current.Store.GetBytes(1);
}
#endif

#if CASE_ENTRY_LIMIT
[Assembly("F04D430101")]
public static class EntryOne { [Process] public static void Process() { } }
[Assembly("F04D430102")]
public static class EntryTwo { [Process] public static void Process() { } }
[Assembly("F04D430103")]
public static class EntryThree { [Process] public static void Process() { } }
[Assembly("F04D430104")]
public static class EntryFour { [Process] public static void Process() { } }
#endif

#if CASE_ENTRY_BOUNDARY
[Assembly("F04D430101")]
public static class EntryOne { [Process] public static void Process() { } }
[Assembly("F04D430102")]
public static class EntryTwo { [Process] public static void Process() { } }
[Assembly("F04D430103")]
public static class EntryThree { [Process] public static void Process() { } }
#endif

#if CASE_TRANSACTION
public static class InvalidTransaction
{
    public static void Run()
    {
        using var scope = new TransactionScope();
        Hardware.Write(0, 1);
        scope.Complete();
    }
}
#endif

#if CASE_CALL_GRAPH
public static class InvalidCallGraph
{
    public static void Run() => Run();
}
#endif

#if CASE_CALL_DEPTH
public static class InvalidCallDepth
{
    public static void M00() => M01();
    private static void M01() => M02();
    private static void M02() => M03();
    private static void M03() => M04();
    private static void M04() => M05();
    private static void M05() => M06();
    private static void M06() => M07();
    private static void M07() => M08();
    private static void M08() => M09();
    private static void M09() => M10();
    private static void M10() => M11();
    private static void M11() => M12();
    private static void M12() => M13();
    private static void M13() => M14();
    private static void M14() => M15();
    private static void M15() => M16();
    private static void M16() => M17();
    private static void M17() => M18();
    private static void M18() => M19();
    private static void M19() => M20();
    private static void M20() => M21();
    private static void M21() => M22();
    private static void M22() => M23();
    private static void M23() => M24();
    private static void M24() => M25();
    private static void M25() => M26();
    private static void M26() => M27();
    private static void M27() => M28();
    private static void M28() => M29();
    private static void M29() => M30();
    private static void M30() => M31();
    private static void M31() => M32();
    private static void M32() { }
}
#endif

#if CASE_NESTED_TYPE
public static class InvalidNestedContainer
{
    public sealed class Nested
    {
        public int Value;
    }
}
#endif

#if CASE_STATIC_FIELD
public sealed class InvalidStaticField
{
    public static int Value;
}
#endif

#if CASE_FIELD_TYPE
public sealed class InvalidFieldType
{
    public byte[] Value = [];
}
#endif

#if CASE_METHOD_IMPL_FLAGS
public static class InvalidMethodImplementationFlags
{
    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    public static void Run() { }
}
#endif

#if CASE_INHERITANCE
public sealed class InvalidInheritance : System.Exception { }
#endif

#if CASE_LITERAL_FIELD_TYPE
public static class InvalidLiteralFieldType
{
    public const string Value = "unsupported";
}
#endif

public static class ValidCollectionExpressions
{
    public static byte[] Empty() => EmptyCore();
    public static int[] Values(int value) => [1, value, 3];
    private static byte[] EmptyCore() => [];
}

public static class ValidConstants
{
    public const int SuccessStatus = 0x9000;
    public static int Read() => SuccessStatus;
}

public sealed class PrivateState
{
    private int value;

    public PrivateState(int value) => this.value = value;
    public int Read() => value;
}

#if CASE_TYPEOF
public static class UnsupportedRuntimeTypeInspection
{
    public static int Run() => typeof(PrivateState) == null ? 0 : 1;
}
#endif

#if CASE_EVENT
public static class UnsupportedEventDeclaration
{
    public static event System.Action? Changed;
}
#endif

#if CASE_STATIC_AUTO_PROPERTY
public static class UnsupportedStaticAutoProperty
{
    public static int Value { get; set; }
}
#endif

#if CASE_AUTO_PROPERTY_FIELD
public sealed class UnsupportedAutoPropertyField
{
    public byte[] Value { get; set; } = [];
}
#endif

#if CASE_INIT_PROPERTY
public sealed class UnsupportedInitProperty
{
    public int Value { get; init; }
}
#endif

#if CASE_REF_RETURN
public sealed class UnsupportedRefReturn
{
    private int value;
    public ref int Value() => ref value;
}
#endif

#if CASE_LOCALS
public static class ExcessiveLocals
{
    public static int Run(int value)
    {
        int v00 = value, v01 = value, v02 = value, v03 = value, v04 = value;
        int v05 = value, v06 = value, v07 = value, v08 = value, v09 = value;
        int v10 = value, v11 = value, v12 = value, v13 = value, v14 = value;
        int v15 = value, v16 = value, v17 = value, v18 = value, v19 = value;
        int v20 = value, v21 = value, v22 = value, v23 = value, v24 = value;
        int v25 = value, v26 = value, v27 = value, v28 = value, v29 = value;
        int v30 = value, v31 = value, v32 = value, v33 = value, v34 = value;
        int v35 = value, v36 = value, v37 = value, v38 = value, v39 = value;
        int v40 = value, v41 = value, v42 = value, v43 = value, v44 = value;
        int v45 = value, v46 = value, v47 = value, v48 = value, v49 = value;
        int v50 = value, v51 = value, v52 = value, v53 = value, v54 = value;
        int v55 = value, v56 = value, v57 = value, v58 = value, v59 = value;
        int v60 = value, v61 = value, v62 = value, v63 = value, v64 = value;
        return v00 + v01 + v02 + v03 + v04 + v05 + v06 + v07 + v08 + v09 +
            v10 + v11 + v12 + v13 + v14 + v15 + v16 + v17 + v18 + v19 +
            v20 + v21 + v22 + v23 + v24 + v25 + v26 + v27 + v28 + v29 +
            v30 + v31 + v32 + v33 + v34 + v35 + v36 + v37 + v38 + v39 +
            v40 + v41 + v42 + v43 + v44 + v45 + v46 + v47 + v48 + v49 +
            v50 + v51 + v52 + v53 + v54 + v55 + v56 + v57 + v58 + v59 +
            v60 + v61 + v62 + v63 + v64;
    }
}
#endif

#if CASE_PARAMETERS
public static class ExcessiveParameters
{
    public static int Run(
        int p00, int p01, int p02, int p03, int p04, int p05, int p06, int p07,
        int p08, int p09, int p10, int p11, int p12, int p13, int p14, int p15,
        int p16, int p17, int p18, int p19, int p20, int p21, int p22, int p23,
        int p24, int p25, int p26, int p27, int p28, int p29, int p30, int p31,
        int p32) => p00 + p32;
}
#endif

#if CASE_PARAMETERS_BOUNDARY
public static class MaximumParameters
{
    public static int Run(
        int p00, int p01, int p02, int p03, int p04, int p05, int p06, int p07,
        int p08, int p09, int p10, int p11, int p12, int p13, int p14, int p15,
        int p16, int p17, int p18, int p19, int p20, int p21, int p22, int p23,
        int p24, int p25, int p26, int p27, int p28, int p29, int p30, int p31) => p00 + p31;
}
#endif

#if CASE_ALLOCATION
public static class ExcessiveAllocation
{
    public static int[] Run() => new int[4097];
}
#endif

#if CASE_ALLOCATION_BOUNDARY
public static class BoundaryAllocation
{
    public static int[] Run() => new int[4094];
}
#endif

#if CASE_ALLOCATION_OVERHEAD
public static class AllocationOverhead
{
    public static int[] Run() => new int[4095];
}
#endif

#if CASE_AGGREGATE_ALLOCATION
public static class AggregateAllocation
{
    public static int Run()
    {
        byte[] first = new byte[8193];
        byte[] second = new byte[8193];
        return first.Length + second.Length;
    }
}
#endif

public static class ConditionalAllocation
{
    public static byte[] Run(bool first) => first ? new byte[9000] : new byte[9000];
}

#if CASE_CALL_ALLOCATION
public static class CallAllocation
{
    public static int Run()
    {
        byte[] first = new byte[8193];
        return first.Length + Allocate().Length;
    }

    private static byte[] Allocate() => new byte[8193];
}
#endif

public static class ConditionalCallAllocation
{
    public static byte[] Run(bool first) => first ? Allocate() : new byte[9000];
    private static byte[] Allocate() => new byte[9000];
}

#if CASE_CALL_OBJECTS
public sealed class TinyObject { }

public static class ExcessiveCallObjects
{
    private static void M00() { _ = new TinyObject(); }
    private static void M01() { M00(); M00(); }
    private static void M02() { M01(); M01(); }
    private static void M03() { M02(); M02(); }
    private static void M04() { M03(); M03(); }
    private static void M05() { M04(); M04(); }
    private static void M06() { M05(); M05(); }
    private static void M07() { M06(); M06(); }
    private static void M08() { M07(); M07(); }
    public static void Run() { M08(); M08(); }
}
#endif

#if CASE_LOOP_ALLOCATION
public static class LoopAllocation
{
    public static int Run(int count)
    {
        int total = 0;
        for (int i = 0; i < count; i++)
        {
            int[] values = new int[1];
            total += values.Length;
        }
        return total;
    }
}
#endif

#if CASE_LOOP_OBJECT_ALLOCATION
public sealed class LoopObjectAllocation
{
    public int Value;

    public static int Run(int count)
    {
        int total = 0;
        while (count > 0)
        {
            LoopObjectAllocation value = new();
            total += value.Value;
            count--;
        }
        return total;
    }
}
#endif

#if CASE_LOOP_COLLECTION_ALLOCATION
public static class LoopCollectionAllocation
{
    public static int Run(int count)
    {
        int total = 0;
        do
        {
            byte[] values = [1, 2];
            total += values.Length;
            count--;
        }
        while (count > 0);
        return total;
    }
}
#endif

#if CASE_SWITCH_LIMIT || CASE_SWITCH_BOUNDARY
public static class ExcessiveSwitch
{
    public static int Expression(int value) => value switch
    {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 5,
        6 => 6,
        7 => 7,
        8 => 8,
        9 => 9,
        10 => 10,
        11 => 11,
        12 => 12,
        13 => 13,
        14 => 14,
        15 => 15,
        16 => 16,
        17 => 17,
        18 => 18,
        19 => 19,
        20 => 20,
        21 => 21,
        22 => 22,
        23 => 23,
        24 => 24,
        25 => 25,
        26 => 26,
        27 => 27,
        28 => 28,
        29 => 29,
        30 => 30,
        31 => 31,
        32 => 32,
        33 => 33,
        34 => 34,
        35 => 35,
        36 => 36,
        37 => 37,
        38 => 38,
        39 => 39,
        40 => 40,
        41 => 41,
        42 => 42,
        43 => 43,
        44 => 44,
        45 => 45,
        46 => 46,
        47 => 47,
        48 => 48,
        49 => 49,
        50 => 50,
        51 => 51,
        52 => 52,
        53 => 53,
        54 => 54,
        55 => 55,
        56 => 56,
        57 => 57,
        58 => 58,
        59 => 59,
        60 => 60,
        61 => 61,
        62 => 62,
        63 => 63,
        64 => 64,
        65 => 65,
        66 => 66,
        67 => 67,
        68 => 68,
        69 => 69,
        70 => 70,
        71 => 71,
        72 => 72,
        73 => 73,
        74 => 74,
        75 => 75,
        76 => 76,
        77 => 77,
        78 => 78,
        79 => 79,
        80 => 80,
        81 => 81,
        82 => 82,
        83 => 83,
        84 => 84,
        85 => 85,
        86 => 86,
        87 => 87,
        88 => 88,
        89 => 89,
        90 => 90,
        91 => 91,
        92 => 92,
        93 => 93,
        94 => 94,
        95 => 95,
        96 => 96,
        97 => 97,
        98 => 98,
        99 => 99,
        100 => 100,
        101 => 101,
        102 => 102,
        103 => 103,
        104 => 104,
        105 => 105,
        106 => 106,
        107 => 107,
        108 => 108,
        109 => 109,
        110 => 110,
        111 => 111,
        112 => 112,
        113 => 113,
        114 => 114,
        115 => 115,
        116 => 116,
        117 => 117,
        118 => 118,
        119 => 119,
        120 => 120,
        121 => 121,
        122 => 122,
        123 => 123,
        124 => 124,
        125 => 125,
        126 => 126,
        127 => 127,
        128 => 128,
        129 => 129,
        130 => 130,
        131 => 131,
        132 => 132,
        133 => 133,
        134 => 134,
        135 => 135,
        136 => 136,
        137 => 137,
        138 => 138,
        139 => 139,
        140 => 140,
        141 => 141,
        142 => 142,
        143 => 143,
        144 => 144,
        145 => 145,
        146 => 146,
        147 => 147,
        148 => 148,
        149 => 149,
        150 => 150,
        151 => 151,
        152 => 152,
        153 => 153,
        154 => 154,
        155 => 155,
        156 => 156,
        157 => 157,
        158 => 158,
        159 => 159,
        160 => 160,
        161 => 161,
        162 => 162,
        163 => 163,
        164 => 164,
        165 => 165,
        166 => 166,
        167 => 167,
        168 => 168,
        169 => 169,
        170 => 170,
        171 => 171,
        172 => 172,
        173 => 173,
        174 => 174,
        175 => 175,
        176 => 176,
        177 => 177,
        178 => 178,
        179 => 179,
        180 => 180,
        181 => 181,
        182 => 182,
        183 => 183,
        184 => 184,
        185 => 185,
        186 => 186,
        187 => 187,
        188 => 188,
        189 => 189,
        190 => 190,
        191 => 191,
        192 => 192,
        193 => 193,
        194 => 194,
        195 => 195,
        196 => 196,
        197 => 197,
        198 => 198,
        199 => 199,
        200 => 200,
        201 => 201,
        202 => 202,
        203 => 203,
        204 => 204,
        205 => 205,
        206 => 206,
        207 => 207,
        208 => 208,
        209 => 209,
        210 => 210,
        211 => 211,
        212 => 212,
        213 => 213,
        214 => 214,
        215 => 215,
        216 => 216,
        217 => 217,
        218 => 218,
        219 => 219,
        220 => 220,
        221 => 221,
        222 => 222,
        223 => 223,
        224 => 224,
        225 => 225,
        226 => 226,
        227 => 227,
        228 => 228,
        229 => 229,
        230 => 230,
        231 => 231,
        232 => 232,
        233 => 233,
        234 => 234,
        235 => 235,
        236 => 236,
        237 => 237,
        238 => 238,
        239 => 239,
        240 => 240,
        241 => 241,
        242 => 242,
        243 => 243,
        244 => 244,
        245 => 245,
        246 => 246,
        247 => 247,
        248 => 248,
        249 => 249,
        250 => 250,
        251 => 251,
        252 => 252,
        253 => 253,
        254 => 254,
        255 => 255,
#if CASE_SWITCH_LIMIT
        256 => 256,
#endif
        _ => -1,
    };
}
#endif

#if CASE_LANGUAGE
public static class InvalidLanguage
{
    public static void Run()
    {
        try { ResponseApdu.Write([1], 0, 1); } catch { }
    }
}
#endif

#if CASE_ASYNC_METHOD
public static class InvalidAsyncMethod
{
    public static async void Run() => ResponseApdu.Write([1], 0, 1);
}
#endif

#if CASE_USING_DECLARATION
public static class InvalidUsingDeclaration
{
    public static void Run()
    {
        using System.IO.MemoryStream stream = new();
        stream.WriteByte(1);
    }
}
#endif

#if CASE_TYPE
public static class InvalidType
{
    public static void Run()
    {
        long value = 1;
        ResponseApdu.Write([(byte)value], 0, 1);
    }
}
#endif

#if CASE_SHAPE
public class InvalidShape
{
    public static int Value;
}
#endif

#if CASE_STATIC_CONSTRUCTOR
public static class InvalidStaticConstructor
{
    static InvalidStaticConstructor() { }
    public static void Run() { }
}
#endif

#if CASE_INTERFACE
public sealed class InvalidInterface : System.IDisposable
{
    public void Dispose() { }
}
#endif

#if CASE_EXTERNAL
public static class InvalidExternalCall
{
    public static int Run(int value) => System.Math.Abs(value);
}
#endif

#if CASE_SYSTEM_SHA256_OVERLOAD
public static class InvalidSystemSha256Overload
{
    public static byte[] Hash(byte[] data) =>
        System.Security.Cryptography.SHA256.HashData(new System.IO.MemoryStream(data));
}
#endif

#if CASE_SYSTEM_RNG_OVERLOAD
public static class InvalidSystemRngOverload
{
    public static int Draw(int maximum) =>
        System.Security.Cryptography.RandomNumberGenerator.GetInt32(maximum);
}
#endif

#if CASE_LIFECYCLE
[Assembly("F04D430021")]
public static class InvalidLifecycle
{
    [Process]
    public static int Process(int value) => value;
}
#endif
