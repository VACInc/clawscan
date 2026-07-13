def scanner($id): .scanners[$id] // {};
def completed($id):
  (scanner($id).status == "completed") and
  (scanner($id).error == "") and
  ((scanner($id).raw | type) == "object");
def clean_static:
  completed("clawscan-static") and
  (scanner("clawscan-static").raw.schemaVersion == "clawscan-static-v1") and
  ((scanner("clawscan-static").raw.findings // null | type) == "array") and
  ((scanner("clawscan-static").raw.findings | length) == 0) and
  ((scanner("clawscan-static").raw.files.omitted // null | type) == "array") and
  ((scanner("clawscan-static").raw.files.omitted | length) == 0) and
  ((scanner("clawscan-static").raw.files.suppressedScanned // 0) == 0) and
  ((scanner("clawscan-static").raw.files.suppressedOmitted // 0) == 0);
def clean_skillspector:
  completed("skillspector") and
  ((scanner("skillspector").raw.issues // null | type) == "array") and
  ((scanner("skillspector").raw.issues | length) == 0) and
  ((scanner("skillspector").raw.risk_assessment.recommendation // "" | ascii_upcase) == "SAFE") and
  ((scanner("skillspector").raw.analysis_completeness.coverage_percent // 0) == 100) and
  ((scanner("skillspector").raw.analysis_completeness.scanned_components // -1) ==
    (scanner("skillspector").raw.analysis_completeness.total_components // -2));
def clean_cisco:
  completed("cisco") and
  (scanner("cisco").raw.is_safe == true) and
  ((scanner("cisco").raw.max_severity // "" | ascii_upcase) == "SAFE") and
  ((scanner("cisco").raw.findings_count // -1) == 0) and
  ((scanner("cisco").raw.findings // null | type) == "array") and
  ((scanner("cisco").raw.findings | length) == 0);
def clean_agentverus:
  completed("agentverus") and
  ((scanner("agentverus").raw.badge // "" | ascii_downcase) == "certified") and
  ((scanner("agentverus").raw.overall // 0) >= 90) and
  ((scanner("agentverus").raw.findings // null | type) == "array") and
  (scanner("agentverus").raw.findings | all(.[];
    ((.severity // "" | ascii_downcase) == "info") and ((.deduction // 0) == 0)));
def expected_plugin_skip($id):
  (scanner($id).status == "skipped") and
  (scanner($id).raw == null) and
  (scanner($id).error == ("Scanner " + $id + " does not support plugin targets."));

. as $artifact |
($artifact.target.kind // "unknown") as $kind |
([
  if ($kind == "skill" or $kind == "plugin") then empty else "unsupported target kind" end,
  if (($artifact.sandbox.mode // "") == "docker") then empty else "free scanners did not run in Docker" end,
  if clean_static then empty else "clawscan-static did not return complete clean evidence" end,
  if $kind == "skill" then
    if clean_skillspector then empty else "skillspector did not return complete clean evidence" end,
    if clean_cisco then empty else "cisco did not return complete clean evidence" end,
    if clean_agentverus then empty else "agentverus did not return complete clean evidence" end
  elif $kind == "plugin" then
    if clean_skillspector then empty else "skillspector did not return complete clean plugin evidence" end,
    if expected_plugin_skip("cisco") then empty else "cisco plugin skip contract changed" end,
    if expected_plugin_skip("agentverus") then empty else "agentverus plugin skip contract changed" end
  else empty end
]) as $failures |
{
  schemaVersion: "observatory.security-gate.v1",
  status: (if ($failures | length) == 0 then "passed" else "failed" end),
  stage: "security-scan",
  reason: (if ($failures | length) == 0 then
    "free/static security scan passed"
  else
    "failed due to security scan"
  end),
  target: {
    kind: $kind,
    id: ($artifact.target.id // null)
  },
  failures: $failures
}
