import org.apache.iotdb.service.rpc.thrift.*;
import org.apache.iotdb.common.rpc.thrift.TSStatus;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.layered.TFramedTransport;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.util.Map;

/** Shared Thrift plumbing for the Apache IoTDB v2.0.10 validation PoCs. */
public final class Common {
  public static final byte VERSION_1 = 1;
  public static final short HANDSHAKE_CONFIGNODE_V2 = 50;
  public static final short HANDSHAKE_DATANODE_V2   = 51;
  public static final short TRANSFER_CONFIG_PLAN     = 200;

  /** Open a framed+binary IClientRPCService client (the DataNode client RPC, default 6667). */
  public static IClientRPCService.Client clientRpc(String host, int port) throws Exception {
    TTransport tr = new TFramedTransport(new TSocket(host, port));
    tr.open();
    return new IClientRPCService.Client(new TBinaryProtocol(tr));
  }

  /** Length-prefixed UTF-8 string, matching IoTDB's ReadWriteIOUtils.write(String, ...). */
  public static void writeStr(DataOutputStream o, String s) throws Exception {
    byte[] b = s.getBytes("UTF-8");
    o.writeInt(b.length);
    o.write(b);
  }

  /** Serialize a pipe handshake V2 param map: int32 count, then (len,key)(len,val) pairs. */
  public static ByteBuffer handshakeBody(Map<String, String> params) throws Exception {
    ByteArrayOutputStream bo = new ByteArrayOutputStream();
    DataOutputStream o = new DataOutputStream(bo);
    o.writeInt(params.size());
    for (Map.Entry<String, String> e : params.entrySet()) {
      writeStr(o, e.getKey());
      writeStr(o, e.getValue());
    }
    return ByteBuffer.wrap(bo.toByteArray());
  }

  public static String ts() {
    // Wall-clock stamp for the transcript. UTC ISO-8601.
    java.time.format.DateTimeFormatter f =
        java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
            .withZone(java.time.ZoneOffset.UTC);
    return f.format(java.time.Instant.now());
  }

  public static String code(TSStatus st) {
    String m = st.getMessage();
    return "code=" + st.getCode() + (m != null && !m.isEmpty()
        ? " msg=" + m.substring(0, Math.min(200, m.length())) : "");
  }
}
