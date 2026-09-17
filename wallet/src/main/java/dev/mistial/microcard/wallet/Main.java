package dev.mistial.microcard.wallet;

import apdu4j.core.BIBO;
import com.google.gson.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.security.*;
import java.util.*;
import javax.smartcardio.TerminalFactory;

public final class Main {
    private static final String VERSION = "0.1-wip";
    private Main() { }

    public static void main(String[] arguments) {
        try { run(arguments); }
        catch (Exception error) { System.err.println("microcard-wallet: " + error.getMessage()); System.exit(1); }
    }

    private static void run(String[] arguments) throws Exception {
        if (arguments.length == 0 || arguments[0].equals("help") || arguments[0].equals("--help")) { usage(); return; }
        if (arguments[0].equals("--version")) { System.out.println("microcard-wallet " + VERSION); return; }
        if (arguments[0].equals("readers")) {
            var readers = TerminalFactory.getDefault().terminals().list();
            if (readers.isEmpty()) System.out.println("No PC/SC readers found.");
            else readers.forEach(reader -> System.out.println(reader.getName()));
            return;
        }
        Options options = Options.parse(arguments[0], Arrays.copyOfRange(arguments, 1, arguments.length));
        switch (arguments[0]) {
            case "demo" -> demo(options);
            case "setup" -> withCard(options, card -> { new WalletCard(card, options.assets()).setup(options.pin(), options.recovery()); return null; });
            case "inventory" -> withCard(options, card -> { printInventory(new WalletCard(card, options.assets()).inventory()); return null; });
            case "sign" -> withCard(options, card -> {
                var wallet = new WalletCard(card, options.assets()); var identity = identity(options.identity());
                byte[] message = options.message().getBytes(StandardCharsets.UTF_8);
                byte[] signature = wallet.sign(identity, options.pin(), message, 0x9000);
                System.out.println(HexFormat.of().formatHex(signature)); return null;
            });
            case "recover" -> withCard(options, card -> {
                boolean ok = new WalletCard(card, options.assets()).recover(identity(options.identity()), options.recovery(), options.newPin());
                if (!ok) throw new IOException("Recovery code rejected");
                System.out.println("Credential recovered."); return null;
            });
            case "interactive" -> interactive(options);
            default -> throw new IllegalArgumentException("Unknown command: " + arguments[0]);
        }
    }

    private static void interactive(Options options) throws Exception {
        Console console = System.console();
        if (console == null) throw new IOException("Interactive entry requires a terminal");
        String action = console.readLine("Action (sign/recover): ").trim().toLowerCase(Locale.ROOT);
        String selectedIdentity = console.readLine("Identity (personal/work): ").trim();
        WalletCard.Identity identity = identity(selectedIdentity);
        switch (action) {
            case "sign" -> {
                char[] pin = console.readPassword("PIN: ");
                String message = console.readLine("Message: ");
                try {
                    withCard(options, card -> {
                        byte[] signature = new WalletCard(card, options.assets()).sign(
                            identity, pin, message.getBytes(StandardCharsets.UTF_8), 0x9000);
                        System.out.println(HexFormat.of().formatHex(signature));
                        return null;
                    });
                } finally { Arrays.fill(pin, '\0'); }
            }
            case "recover" -> {
                char[] recovery = console.readPassword("Recovery code: ");
                char[] newPin = console.readPassword("New PIN: ");
                try {
                    withCard(options, card -> {
                        if (!new WalletCard(card, options.assets()).recover(identity, recovery, newPin))
                            throw new IOException("Recovery code rejected");
                        System.out.println("Credential recovered.");
                        return null;
                    });
                } finally {
                    Arrays.fill(recovery, '\0');
                    Arrays.fill(newPin, '\0');
                }
            }
            default -> throw new IllegalArgumentException("Action must be sign or recover");
        }
    }

    private static void demo(Options supplied) throws Exception {
        Path workspace = supplied.workspace() != null ? supplied.workspace() : Files.createTempDirectory("microcard-wallet-");
        if (supplied.workspace() != null && Files.exists(workspace)) {
            try (var entries = Files.list(workspace)) {
                if (entries.findAny().isPresent()) throw new IOException("The demo requires a new or empty workspace");
            }
        }
        Files.createDirectories(workspace);
        Path keys = workspace.resolve("development-management.key");
        Path state = workspace.resolve("card-state");
        if (Files.notExists(keys)) {
            if (Files.exists(state)) throw new IOException("Refusing to create keys beside existing card state");
            byte[] value = new byte[32]; for (int index = 0; index < value.length; index++) value[index] = (byte)index;
            Files.write(keys, value, StandardOpenOption.CREATE_NEW);
            try { Files.setPosixFilePermissions(keys, Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)); }
            catch (UnsupportedOperationException ignored) { }
        }
        Options options = supplied.withWorkspace(workspace, keys, state);
        System.out.println("MicroCard credential wallet " + VERSION);
        System.out.println("Development demonstration only. State: " + workspace.toAbsolutePath());
        System.out.println("Taking ownership and creating Personal and Work identities...");
        withCard(options, card -> {
            WalletCard wallet = new WalletCard(card, options.assets());
            wallet.setup("1234".toCharArray(), "12345678".toCharArray());
            printInventory(wallet.inventory());
            byte[] challenge = new byte[32]; new SecureRandom().nextBytes(challenge);
            byte[] personalKey = wallet.publicKey(WalletCard.PERSONAL);
            byte[] workKey = wallet.publicKey(WalletCard.WORK);
            if (MessageDigest.isEqual(personalKey, workKey)) throw new IOException("Identity keys unexpectedly match");
            byte[] personalSignature = wallet.sign(WalletCard.PERSONAL, "1234".toCharArray(), challenge, 0x9000);
            byte[] workSignature = wallet.sign(WalletCard.WORK, "1234".toCharArray(), challenge, 0x9000);
            if (!WalletCard.verifyP256(personalKey, challenge, personalSignature)
                || !WalletCard.verifyP256(workKey, challenge, workSignature)) throw new IOException("Host signature verification failed");
            if (WalletCard.verifyP256(workKey, challenge, personalSignature)
                || WalletCard.verifyP256(personalKey, challenge, workSignature)) throw new IOException("Cross-identity signature isolation failed");
            System.out.println("Personal key: " + fingerprint(personalKey));
            System.out.println("Work key:     " + fingerprint(workKey));
            System.out.println("Fresh challenge signatures verified. Cross-identity verification rejected.");
            DemoCertificates.Result personalCertificate = DemoCertificates.issue(workspace.resolve("certificates"), "Personal", personalKey);
            DemoCertificates.Result workCertificate = DemoCertificates.issue(workspace.resolve("certificates"), "Work", workKey);
            System.out.println("Host-issued demonstration certificates: " + personalCertificate.credential() + ", " + workCertificate.credential());

            for (int attempt = 0; attempt < 3; attempt++) wallet.sign(WalletCard.PERSONAL, "0000".toCharArray(), challenge, 0x6982);
            if (wallet.retries(WalletCard.PERSONAL) != 0) throw new IOException("PIN retry floor did not reach zero");
            if (!wallet.recover(WalletCard.PERSONAL, "12345678".toCharArray(), "2468".toCharArray())) throw new IOException("Recovery failed");
            byte[] recovered = wallet.sign(WalletCard.PERSONAL, "2468".toCharArray(), challenge, 0x9000);
            if (!WalletCard.verifyP256(personalKey, challenge, recovered)) throw new IOException("Recovered signature failed");
            System.out.println("PIN exhaustion persisted and recovery restored signing without replacing the key.");
            rejectionChecks(card, wallet, options.assets());
            return null;
        });

        System.out.println("Restarting the simulator against the same encrypted journal...");
        withCard(options, card -> {
            WalletCard wallet = new WalletCard(card, options.assets());
            byte[] challenge = "post-restart challenge".getBytes(StandardCharsets.UTF_8);
            byte[] key = wallet.publicKey(WalletCard.PERSONAL);
            byte[] signature = wallet.sign(WalletCard.PERSONAL, "2468".toCharArray(), challenge, 0x9000);
            if (!WalletCard.verifyP256(key, challenge, signature)) throw new IOException("Post-restart signature failed");
            if (!new String(wallet.publicData(WalletCard.WORK), StandardCharsets.UTF_8).equals("Work identity")) throw new IOException("Work identity did not persist");
            System.out.println("Restart verified: both identities and the recovered Personal credential persisted.");
            return null;
        });
        System.out.println("PASS: signed loading, GPPro SCP03, native P-256, PIN recovery, persistence and SSD isolation");
    }

    private static void rejectionChecks(CardConnection card, WalletCard wallet, Path assets) throws Exception {
        WalletCard.Domain personal = wallet.inventory().stream().filter(item -> item.id().equals(WalletCard.PERSONAL.domain())).findFirst().orElseThrow();
        byte[] wrongSigner = Packages.create(assets, WalletCard.PERSONAL.asset(), personal.id(), personal.incarnation(), WalletCard.WORK.signerSeed());
        Packages.upload(card, wrongSigner, 0x6985);
        byte[] wrongIncarnation = personal.incarnation().clone(); wrongIncarnation[0] ^= 1;
        Packages.upload(card, Packages.create(assets, WalletCard.PERSONAL.asset(), personal.id(), wrongIncarnation, WalletCard.PERSONAL.signerSeed()), 0x6985);

        String rejectId = "wallet-reject";
        if (wallet.inventory().stream().noneMatch(item -> item.id().equals(rejectId))) card.command(0xE0, rejectId.getBytes(StandardCharsets.US_ASCII));
        WalletCard.Domain reject = wallet.inventory().stream().filter(item -> item.id().equals(rejectId)).findFirst().orElseThrow();
        JsonObject metadata = JsonParser.parseString(Files.readString(assets.resolve(WalletCard.PERSONAL.asset() + ".json"))).getAsJsonObject();
        metadata.getAsJsonArray("dependencies").get(0).getAsJsonObject().add("signer", byteArray(Packages.publicKey(WalletCard.WORK.signerSeed())));
        byte[] badDependency = Packages.create(Files.readAllBytes(assets.resolve(WalletCard.PERSONAL.asset() + ".mca")), metadata,
            reject.id(), reject.incarnation(), WalletCard.PERSONAL.signerSeed());
        Packages.upload(card, badDependency, 0x6985);
        WalletCard.Domain unchanged = wallet.inventory().stream().filter(item -> item.id().equals(rejectId)).findFirst().orElseThrow();
        if (unchanged.bound() || unchanged.assemblies() != 0) throw new IOException("Rejected package changed SSD binding");
        System.out.println("Substituted signer, old incarnation and incorrect dependency pin were rejected.");
    }

    private static JsonArray byteArray(byte[] value) { JsonArray result = new JsonArray(); for (byte b : value) result.add(b & 255); return result; }
    private static String fingerprint(byte[] value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
        return HexFormat.ofDelimiter(":").withUpperCase().formatHex(Arrays.copyOf(digest, 8));
    }
    private static WalletCard.Identity identity(String value) { return switch (value.toLowerCase(Locale.ROOT)) {
        case "personal" -> WalletCard.PERSONAL; case "work" -> WalletCard.WORK;
        default -> throw new IllegalArgumentException("Identity must be personal or work");
    }; }
    private static void printInventory(List<WalletCard.Domain> domains) {
        System.out.println("Domains:");
        for (var domain : domains) System.out.printf("  %-16s bound=%-5s assemblies=%d instances=%d records=%d%n",
            domain.id(), domain.bound(), domain.assemblies(), domain.instances(), domain.records());
    }

    private interface CardAction<T> { T run(CardConnection card) throws Exception; }
    private static <T> T withCard(Options options, CardAction<T> action) throws Exception {
        byte[] keys = Files.readAllBytes(options.managementKey());
        BIBO transport = options.reader() != null ? CardConnection.reader(options.reader())
            : CardConnection.simulator(options.simulator(), options.managementKey(), options.state());
        try (var card = new CardConnection(transport, keys, options.trace())) { return action.run(card); }
        finally { Arrays.fill(keys, (byte)0); }
    }

    private static void usage() {
        System.out.println("""
            MicroCard credential wallet 0.1-wip
            usage:
              microcard-wallet demo --sim PATH --assets DIR [--workspace DIR] [--trace]
              microcard-wallet setup|inventory --sim PATH --assets DIR --state PATH --management-key PATH
              microcard-wallet sign --identity personal|work --pin 1234 --message TEXT [connection options]
              microcard-wallet recover --identity personal|work --recovery 12345678 --new-pin 2468 [connection options]
              microcard-wallet interactive [connection options]
              microcard-wallet readers

            Use --reader NAME instead of --sim/--state for PC/SC. Secrets supplied on a command line may be visible
            to local process inspection; the guided demo uses fixed, explicitly development-only values.
            """);
    }

    private record Options(Path simulator, String reader, Path assets, Path state, Path managementKey,
                           Path workspace, boolean trace, String identity, char[] pin, char[] recovery,
                           char[] newPin, String message) {
        static Options parse(String command, String[] arguments) {
            Map<String,String> values = new HashMap<>(); boolean trace = false;
            for (int i = 0; i < arguments.length; i++) {
                if (arguments[i].equals("--trace")) { trace = true; continue; }
                if (!arguments[i].startsWith("--") || i + 1 == arguments.length) throw new IllegalArgumentException("Invalid option: " + arguments[i]);
                values.put(arguments[i++].substring(2), arguments[i]);
            }
            Path workspace = path(values, "workspace"); Path management = path(values, "management-key"); Path state = path(values, "state");
            Path simulator = path(values, "sim"); String reader = values.get("reader");
            if ((simulator == null) == (reader == null)) throw new IllegalArgumentException("Choose exactly one of --sim or --reader");
            if (!command.equals("demo") && management == null) throw new IllegalArgumentException("--management-key is required");
            if (!command.equals("demo") && simulator != null && state == null) throw new IllegalArgumentException("--state is required with --sim");
            return new Options(simulator, reader, requiredPath(values, "assets"), state, management,
                workspace, trace, values.getOrDefault("identity", "personal"), chars(values, "pin", "1234"),
                chars(values, "recovery", "12345678"), chars(values, "new-pin", "2468"), values.getOrDefault("message", "MicroCard challenge"));
        }
        Options withWorkspace(Path value, Path keys, Path cardState) { return new Options(simulator, reader, assets, cardState, keys, value, trace, identity, pin, recovery, newPin, message); }
        private static Path path(Map<String,String> values, String key) { return values.containsKey(key) ? Path.of(values.get(key)) : null; }
        private static Path requiredPath(Map<String,String> values, String key) { Path value = path(values, key); if (value == null) throw new IllegalArgumentException("--" + key + " is required"); return value; }
        private static char[] chars(Map<String,String> values, String key, String fallback) { return values.getOrDefault(key, fallback).toCharArray(); }
    }
}
