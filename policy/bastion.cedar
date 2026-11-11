// Bastion action policy (Cedar). The gateway evaluates every proposed action against
// this file without a model. Principals are agents, actions are the executor's fixed
// action names, and the context carries the verdict the action is based on.
//
// The gateway asks twice: first with context.human_approval = false. If that is allowed,
// the action is sent as automatic. If not, it asks again with human_approval = true; if
// that is allowed, the action is sent as "needs a passkey approval". Otherwise it is
// dropped. The executor on the Mac re-checks every target regardless of this policy.

// ---- Tier 1: automatic, reversible containment ------------------------------------

@id("sentry-auto-contain")
permit (
  principal == Agent::"sentry",
  action in [Action::"suspend_process", Action::"quarantine_file"],
  resource
) when {
  context.verdict == "malicious" && context.confidence >= 80
};

@id("anchor-auto-contain")
permit (
  principal == Agent::"anchor",
  action == Action::"disable_launch_item",
  resource
) when {
  context.verdict == "malicious" && context.confidence >= 80
};

// ---- Tier 1 with a human approval: suspicious is enough ---------------------------

@id("contain-with-approval")
permit (
  principal,
  action in [Action::"suspend_process", Action::"quarantine_file", Action::"disable_launch_item"],
  resource
) when {
  context.human_approval && ["malicious", "suspicious"].contains(context.verdict)
};

// ---- Tier 2: permanent removal of something already contained ---------------------

@id("remove-with-approval")
permit (
  principal == Agent::"warden",
  action in [Action::"delete_quarantined", Action::"delete_disabled_item"],
  resource
) when {
  context.human_approval
};

// ---- Guardrails (forbid always wins over permit) ----------------------------------

@id("tier2-never-automatic")
forbid (
  principal,
  action in [Action::"delete_quarantined", Action::"delete_disabled_item"],
  resource
) unless {
  context.human_approval
};

@id("execution-actions-belong-to-sentry")
forbid (
  principal,
  action in [Action::"suspend_process", Action::"quarantine_file"],
  resource
) unless {
  principal == Agent::"sentry"
};

@id("persistence-actions-belong-to-anchor")
forbid (
  principal,
  action == Action::"disable_launch_item",
  resource
) unless {
  principal == Agent::"anchor"
};

@id("weak-rules-never-act-alone")
forbid (principal, action, resource)
when {
  !context.human_approval && ["low", "informational"].contains(context.rule_severity)
};

// System tools such as osascript or curl can be suspended while they are being misused,
// but their files are never moved.
@id("never-quarantine-system-files")
forbid (principal, action == Action::"quarantine_file", resource)
when {
  resource.path like "/System/*" || resource.path like "/usr/*" ||
  resource.path like "/sbin/*" || resource.path like "/bin/*" ||
  resource.path like "/Library/*" || resource.path like "/Applications/*" ||
  resource.path like "/opt/*"
};

@id("protected-programs")
forbid (principal, action, resource)
when {
  resource has path &&
  (resource.path like "/System/*" || resource.path like "/usr/libexec/*" ||
   resource.path like "/sbin/*" || resource.path like "/usr/sbin/*" ||
   resource.path like "/opt/bastion/*" || resource.path like "/opt/osquery/*" ||
   resource.path like "/Library/Application Support/Bastion/*" ||
   resource.path like "/Applications/Santa.app/*" ||
   resource.path like "/Applications/LuLu.app/*" ||
   resource.path like "/Applications/BlockBlock Helper.app/*" ||
   resource.path like "/Applications/Tailscale.app/*" ||
   resource.path like "/Applications/OrbStack.app/*")
};
