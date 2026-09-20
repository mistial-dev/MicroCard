package dev.mistial.tools.openfips201.nist;

import dev.mistial.tools.openfips201.provisioning.ConformancePackage;
import dev.mistial.tools.openfips201.provisioning.ConformanceProvisioner;
import dev.mistial.tools.openfips201.provisioning.IcamCardFolder;
import java.nio.file.Path;
import java.util.List;

/** Exercises original ICAM object bytes; does not claim private-key conformance. */
final class MicroCardNistObjects {
    public static void main(String[] args) throws Exception {
        var original = IcamCardFolder.load(Path.of(args[0]));
        var objects = new ConformancePackage(original.credentialId, original.sourceDirectory,
            original.pin, original.puk, null, original.dataObjects, List.of());
        try (var card = new MicroCardNistTransport()) {
            // Upstream closes SCP03 before reopening the simulator for plain readback.
            var report = ConformanceProvisioner.provision(card::openBibo,
                MicroCardNistProfile.scp(card), objects, System.out);
            if (report.objectsCreated != objects.dataObjects.size() || report.keysImported != 0)
                throw new IllegalStateException("Unexpected object provisioning count");
            System.out.printf("PASS: %d original ICAM objects written and checked after reopening; %d private keys not exercised%n",
                report.objectsCreated, original.keys.size());
        }
    }
}
