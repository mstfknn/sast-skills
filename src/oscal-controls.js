/**
 * Maps each detection skill to the NIST SP 800-53 Rev 5 controls whose objective
 * a finding from that skill puts in doubt. Control ids use the OSCAL catalog
 * spelling (lowercase, dotted enhancements), so they drop straight into an
 * assessment's `reviewed-controls` and into each finding's `target-id`.
 *
 * Only detection skills appear here — the four recon/synthesis skills
 * (sast-analysis, sast-stack, sast-report, sast-triage) never emit findings.
 */
export const SKILL_CONTROLS = {
  // --- Injection ------------------------------------------------------------
  'sast-sqli': ['si-10'],
  'sast-nosql': ['si-10'],
  'sast-ldap': ['si-10'],
  'sast-xpath': ['si-10'],
  'sast-elinj': ['si-10'],
  'sast-ssti': ['si-10'],
  'sast-crlf': ['si-10'],
  'sast-csvinj': ['si-10', 'si-15'],
  'sast-xss': ['si-10', 'si-15'],
  'sast-xxe': ['si-10', 'sc-7'],
  'sast-rce': ['si-10', 'cm-7'],
  'sast-deser': ['si-10', 'si-7'],
  'sast-prototype': ['si-10', 'si-7'],
  'sast-massassign': ['si-10', 'ac-3'],
  'sast-zipslip': ['si-10', 'ac-3'],
  'sast-unsafeconsumption': ['si-10', 'ac-4'],
  'sast-dangerousapi': ['si-10', 'cm-7'],

  // --- Access control -------------------------------------------------------
  'sast-missingauth': ['ac-3', 'ac-6', 'ia-2'],
  'sast-idor': ['ac-3'],
  'sast-pathtraversal': ['ac-3', 'si-10'],
  'sast-excessivedata': ['ac-21', 'ac-3'],
  'sast-routeinventory': ['cm-7', 'ac-3'],
  'sast-graphql': ['ac-3', 'sc-5'],

  // --- Identity, session, transport, crypto ---------------------------------
  'sast-oauth': ['ia-2', 'ia-8', 'sc-23'],
  'sast-jwt': ['ia-5', 'sc-23'],
  'sast-session': ['ac-12', 'sc-23'],
  'sast-cookieflags': ['sc-8', 'sc-23'],
  'sast-csrf': ['sc-23', 'si-10'],
  'sast-tls': ['sc-8', 'sc-23'],
  'sast-hardcodedsecrets': ['ia-5', 'sc-12'],
  'sast-crypto': ['sc-13', 'sc-28'],

  // --- Boundary protection & request forgery --------------------------------
  'sast-ssrf': ['sc-7', 'ac-4'],
  'sast-ssrfimds': ['sc-7', 'ac-6'],
  'sast-cors': ['ac-4', 'sc-7'],
  'sast-openredirect': ['si-10', 'sc-7'],
  'sast-postmessage': ['ac-4', 'si-10'],
  'sast-secheaders': ['cm-6', 'sc-8'],

  // --- Availability ---------------------------------------------------------
  'sast-ratelimit': ['sc-5'],
  'sast-redos': ['sc-5', 'si-10'],
  'sast-xmlbomb': ['sc-5', 'si-10'],

  // --- Data handling, logging, integrity ------------------------------------
  'sast-pii': ['au-9', 'si-11'],
  'sast-errorhandling': ['si-11'],
  'sast-fileupload': ['si-3', 'si-10'],
  'sast-race': ['si-7', 'ac-3'],

  // --- Supply chain, configuration, CI/CD -----------------------------------
  'sast-deps': ['ra-5', 'sa-15', 'sr-3'],
  'sast-depconfusion': ['sr-3', 'sr-11'],
  'sast-lockfile': ['sr-4', 'sr-11'],
  'sast-iac': ['cm-6', 'cm-7'],
  'sast-configrce': ['cm-6', 'si-7'],
  'sast-cloudsdk': ['ac-6', 'cm-6'],
  'sast-pipelineinj': ['si-10', 'sa-15'],

  // --- Business logic -------------------------------------------------------
  'sast-businesslogic': ['sa-11', 'ac-3'],
  'sast-paymentlogic': ['sa-11', 'si-10'],

  // --- Agentic / LLM runtime ------------------------------------------------
  // SP 800-53 Rev 5 predates this threat class, so there is no purpose-built
  // control to point at. Rather than dumping the whole class into ra-5 — which
  // tells an auditor nothing beyond "a scanner ran" — each skill maps to the
  // existing control whose *objective* the failure actually defeats: an
  // over-privileged agent identity is a least-privilege (ac-6) failure whatever
  // the runtime, and untrusted text steering a model is still an information
  // input validation (si-10) failure. Revisit if NIST publishes an AI overlay.
  'sast-promptinjection': ['si-10'],
  'sast-llmoutput': ['si-15', 'si-10'],
  'sast-excessiveagency': ['ac-6', 'cm-7'],
  'sast-toolcalling': ['ac-6', 'si-10'],
  'sast-agentidentity': ['ac-6', 'ia-2'],
  'sast-memorypoison': ['si-7', 'ac-4'],
  'sast-ragleak': ['ac-4', 'ac-21'],
  'sast-systempromptleak': ['ac-21', 'sc-4'],
  'sast-llmdos': ['sc-5'],
  'sast-mcpsec': ['sr-3', 'si-7'],
  'sast-skillaudit': ['si-7', 'cm-14'],
};

/**
 * Vulnerability Monitoring and Scanning — the honest fallback for a skill with
 * no mapping yet. A newly scaffolded skill still produces a valid, if
 * unspecific, OSCAL document instead of having its findings dropped.
 */
export const FALLBACK_CONTROLS = ['ra-5'];

/** @returns {string[]} control ids for a skill; never empty. */
export function controlsForSkill(skill) {
  return SKILL_CONTROLS[skill] ?? FALLBACK_CONTROLS;
}
