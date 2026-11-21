/**
 * @name Unredacted operation evidence is persisted
 * @description Operation output must pass through the returned StreamRedactor value before evidence persistence.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id cops/unredacted-evidence-write
 * @tags security
 *       external/cwe/cwe-532
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/** The repository's evidence store, rather than arbitrary Python file writes. */
private predicate inEvidenceRecorder(Scope scope) {
  scope.(Function).getEnclosingScope().(Class).getName() = "EvidenceRecorder" and
  scope.getEnclosingModule().getFile().getRelativePath().matches("%cops/execution/evidence.py")
}

private predicate isRecorderMethodCall(DataFlow::CallCfgNode call, string name) {
  inEvidenceRecorder(call.getScope()) and
  call.asExpr().(Call).getFunc().(Attribute).getName() = name and
  call.asExpr().(Call).getFunc().(Attribute).getObject().(Name).getId() = "self"
}

/** Match the repository helper's import binding, including `from ... import ... as ...`. */
private predicate isImportedHelper(DataFlow::CallCfgNode call, string moduleName, string member) {
  exists(Import statement, Alias binding, ImportMember imported, Name function |
    binding = statement.getAName() and
    imported = binding.getValue() and
    imported.getModule().(ImportExpr).getImportedModuleName() = moduleName and
    imported.getName() = member and
    function = call.asExpr().(Call).getFunc() and
    function.getVariable() = binding.getAsname().(Name).getVariable()
  )
}

/** Only the returned value is sanitized. Calling a redactor does not clean its argument. */
private predicate isRedactedReturn(DataFlow::Node node) {
  exists(DataFlow::CallCfgNode call, Attribute method, Attribute receiver |
    node = call and
    inEvidenceRecorder(call.getScope()) and
    method = call.asExpr().(Call).getFunc() and
    method.getName() = ["redact", "redact_string", "redact_bytes"] and
    receiver = method.getObject() and
    receiver.getName() = "redactor" and
    receiver.getObject().(Name).getId() = "self"
  )
}

module EvidenceConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::ParameterNode parameter |
      source = parameter and
      inEvidenceRecorder(parameter.getScope()) and
      parameter.getScope().(Function).getName() = "record_step_output" and
      parameter.getParameter().getName() = ["stdout", "stderr", "error", "action", "artifact_outputs"]
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallCfgNode call |
      isRecorderMethodCall(call, ["_write_reserved_artifact", "_write_portable_reserved_artifact"]) and
      (sink = call.getArg(1) or sink = call.getArgByName("content"))
    )
  }

  predicate isBarrier(DataFlow::Node node) { isRedactedReturn(node) }

  predicate isAdditionalFlowStep(DataFlow::Node before, DataFlow::Node after) {
    // Persisted evidence contains dictionaries nested inside a payload and envelope.
    exists(Dict dictionary |
      before.asExpr() = dictionary.getAValue() and after.asExpr() = dictionary
    )
    or
    exists(List list | before.asExpr() = list.getAnElt() and after.asExpr() = list)
    or
    exists(DataFlow::CallCfgNode call |
      // Serialization and schema validation preserve confidential data, not sanitize it.
      isImportedHelper(call, "cops.evidence.contract", "build_envelope") and
      before = call.getArgByName("payload") and after = call
    )
    or
    exists(DataFlow::CallCfgNode call |
      isImportedHelper(call, "cops.evidence.canonical", "canonical") and
      before = call.getArg(0) and after = call
    )
    or
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("hashlib").getMember("sha256").getACall() and
      before = call.getArg(0) and after = call
    )
    or
    exists(DataFlow::CallCfgNode call, Attribute method |
      method = call.asExpr().(Call).getFunc() and
      method.getName() = ["digest", "hexdigest"] and
      before.asExpr() = method.getObject() and after = call
    )
  }
}

module EvidenceFlow = TaintTracking::Global<EvidenceConfiguration>;
import EvidenceFlow::PathGraph

from EvidenceFlow::PathNode source, EvidenceFlow::PathNode sink
where EvidenceFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Operation evidence from $@ reaches persistent storage without using a returned redacted value.",
  source.getNode(), "this captured value"
