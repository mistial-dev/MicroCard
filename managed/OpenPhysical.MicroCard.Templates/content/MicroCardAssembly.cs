using MicroCard.Framework;

[CardAssembly("MicroCardAssemblyAid")]
public static class MicroCardAssembly
{
    public static void Install() { }

    public static void Select() { }

    public static void Deselect() { }

    public static void Process()
    {
        ResponseApdu.SetStatus(0x9000);
    }

    public static void Uninstall() { }
}
