public static class PackageConsumer
{
#if INVALID_PACKAGE_CASE
    public static long Value() => 1;
#else
    public static int Value() => 1;
#endif
}
