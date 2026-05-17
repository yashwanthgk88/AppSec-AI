# Predictive AppSec at the Speed of DevOps: A Human-in-the-Loop AI/ML Pipeline for Continuous Insider-Threat Defence Across the Software Development Lifecycle

**Submitted to:** c0c0n 2026 — International Conference on Hacking & Cyber Security Briefing, Kerala, India
**Track:** Defensive Research / AI in Cyber Security / Application Security
**Authors:** Abinesh Kamal, Yashwanth Gopi Krishnamoorthy, Niraj Shetty
**Word count:** ~2,950

---

## Abstract

The 2024-2026 threat landscape has shifted decisively toward insider risk, software supply-chain compromise, and rapid-tempo abuse of legitimate code paths. Conventional Application Security (AppSec) tooling, optimised for known Common Vulnerabilities and Exposures (CVE) detection at runtime, struggles to contextualise the upstream signals that distinguish a malicious change from routine engineering: risky abuse cases hidden inside product user stories, architectural decisions that silently create new attack paths, vulnerabilities introduced at the developer's keystroke, and behavioural anomalies that surface in commit streams long before any vulnerability is exploited. This paper presents an integrated AI/ML platform that converts these scattered, lifecycle-distributed signals into a continuous, *shift-left* defensive pipeline spanning the entire Software Development Lifecycle (SDLC). The platform comprises four interlocking components: *SecureReq*, a Large Language Model (LLM)-driven analyser that derives abuse cases, STRIDE threats, and testable security requirements from user stories, with an explicit insider-threat mode; a *Continuous Threat-Modelling Pipeline* that ingests free-form architecture descriptions and diagrams to produce STRIDE-tagged threats with CWE and MITRE ATT&CK mapping, multi-hop attack paths, FAIR-based financial-loss quantification, and *stable threat identifiers* that persist across architectural revisions; a *VS Code Integrated Development Environment (IDE) Extension* that places the same insider-threat detection corpus directly into the developer's editor as native diagnostics with AI-suggested fixes, surfacing vulnerabilities at the moment of authorship rather than at code review or build; and a *GitHub Commit Monitor* that scores every commit through ten deterministic insider-threat detectors, learns per-developer behavioural baselines from a rolling 60-commit window, and flags statistical anomalies with on-demand AI triage. The system embodies a deliberate hybrid design: deterministic scaffolding for reproducibility and audit, with LLMs confined to enrichment, narrative explanation, and analyst-invoked investigation — never automated severity decisions. A single shared rule corpus and AI-provider abstraction guarantee that the same threat is detected identically from IDE keystroke through commit time, eliminating the rule-fragmentation typical of multi-tool security stacks. An in-context feedback loop adapts outputs to each security team's preferences without model fine-tuning. We argue that this architecture directly answers c0c0n 2026's call for *intelligent, adaptive, and predictive* AI-driven cyber defence while preserving the human oversight that complex insider threats demand.

---

## 1. Introduction

The economic centre of gravity in cyber risk has shifted. According to recent industry reporting (IBM Cost of a Data Breach 2024; Verizon DBIR 2024), insider-driven incidents now command among the highest mean breach costs and longest dwell times of any threat category, while supply-chain compromise has emerged as a board-level risk for regulated industries. Both categories share a defining property: the malicious activity flows through *legitimate* channels — authenticated commits, approved pull requests, sanctioned dependency updates, or procedurally-permitted access — rendering signature-based and runtime-only defences structurally inadequate.

Yet the discriminating signals are not absent; they are merely distributed across the Software Development Lifecycle (SDLC) and routinely discarded. A user story that handles refunds carries implicit abuse-case risk before code is written; an architecture revision that places a new service in the demilitarised zone (DMZ) creates attack paths that may never be enumerated; a commit that quietly removes a Static Application Security Testing (SAST) step from a Continuous Integration (CI) pipeline contains the highest-confidence signal a defender will receive. Yet the state of the art treats each as an isolated artefact: threat-modelling workshops generate static documents; SAST scanners have no notion of architectural risk surface; commit-level monitoring is typically limited to secret detection. No widely deployed system fuses these signals into a single, continuous, *predictive* defensive pipeline.

This paper presents such a system, operationalising three observations: (1) the insider-threat signals that matter at commit time also matter, earlier and more cheaply, in stories and architecture; (2) LLMs can reduce the human cost of converting unstructured artefacts into structured threat data, *provided their role is restricted to enrichment rather than judgement*; (3) per-developer behavioural baselines computed deterministically from commit history provide a robust statistical complement to LLM-driven analysis.

Our contributions are: (i) the design and implementation of a four-stage, SDLC-spanning AppSec pipeline (SecureReq → Threat Modelling → VS Code IDE Extension → Commit Monitor) that realises shift-left from product backlog to running code under a single shared rule corpus; (ii) a hybrid deterministic-plus-LLM architecture that preserves auditability while leveraging modern AI capabilities; (iii) a *stable threat-identifier* mechanism that enables continuous, version-aware threat modelling; (iv) a behavioural-baseline engine for commit-level insider-threat anomaly detection using per-developer z-score analysis; and (v) cross-component integration patterns wherein SecureReq abuse cases are injected as explicit threats into the threat model, the threat model is consumed as a Bayesian prior to re-rank SAST findings, and IDE diagnostics share the same rule and false-positive state as the commit-time scanner.

This paper aligns with c0c0n 2026's stated theme of *intelligent, adaptive, predictive* AI/ML-driven cyber-resilience and with the conference Chairman's explicit emphasis on the indispensability of human oversight in handling complex attacks and ethical concerns. The platform we describe places that emphasis at the centre of its architecture.

---

## 2. Background and Related Work

**Threat modelling frameworks.** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) remains the dominant industry taxonomy but is typically applied through manual workshops that age rapidly. PASTA, Trike, and OCTAVE address some limitations at the cost of greater analyst burden. The Factor Analysis of Information Risk (FAIR) standard provides a quantitative complement, decomposing risk into Loss Event Frequency and Loss Magnitude, while MITRE ATT&CK contributes adversary-perspective Tactics and Techniques grounded in real-world behaviour.

**Compliance frameworks.** OWASP Application Security Verification Standard (ASVS) v4 organises controls into 14 verticals (V1 Architecture–V14 Configuration); PCI-DSS defines twelve requirement clusters. Both are widely demanded by audit functions but are mapped to engineering work-items only retroactively.

**Behavioural analytics and LLMs in security.** User and Entity Behaviour Analytics (UEBA) is mature in network and endpoint domains but has seen limited adoption over source-control telemetry; existing commit-level work focuses on secret detection (gitleaks, trufflehog) rather than per-developer baselining. Recent LLM work demonstrates utility for vulnerability triage and report summarisation, but naïve LLM deployment risks hallucination, reproducibility loss, and unbounded cost. Our design responds by confining LLM use to enrichment of pre-ranked items, parsing of unstructured input, and on-demand investigation — never authoritative scoring.

**Continuous threat modelling.** Threagile, IriusRisk, and the Microsoft Threat Modelling Tool offer code-driven or template-driven model generation but lack version-aware lifecycle tracking — a re-run produces a fresh document with no stable identity for individual threats. Our *stable threat identifier* mechanism, hashing (STRIDE category, target component, attack vector), addresses this gap and enables auditor-grade diff views across architectural revisions.

The platform presented here is, to the authors' knowledge, the first to fuse story-level analysis, continuous threat modelling, IDE-resident real-time diagnostics, and behaviourally-baselined commit monitoring into a single, hybrid, human-in-the-loop pipeline that explicitly targets insider threats across the SDLC under one unified rule corpus.

---

## 3. System Architecture

### 3.1 Overview

The platform is structured as four loosely-coupled components sharing a common data model, a common rule corpus, and a common AI-provider abstraction. Each component is independently deployable, but the highest defensive value emerges from their composition. An overview is shown conceptually as: **Stories → SecureReq → abuse cases & requirements → Threat Modelling → STRIDE / Attack Paths / FAIR → IDE Extension (real-time diagnostics during authoring) → Commit Monitor → behavioural baselines → anomaly feed.** Each arrow represents both a data dependency and a defensive amplification: signals propagate forward, and high-risk findings flow back to inform earlier stages.

### 3.2 SecureReq: From User Story to Security Backlog

SecureReq accepts user stories — manually entered, or synchronised from Jira, Azure DevOps, or ServiceNow — and produces a structured security analysis comprising 5-7 abuse cases, 6+ STRIDE-categorised threats, 10-15 actionable security requirements with testable acceptance criteria, a risk score on a 0-100 scale, and automatic mappings to OWASP ASVS V1-V14 and PCI-DSS Req 1-12 controls.

The pipeline executes in ten deterministic stages plus a single LLM invocation. The prompt is built dynamically from the story, recent positive/negative analyst feedback supplied as in-context few-shot examples, and optional insider-threat extensions when toggled. Model parameters use `max_tokens=8192` against Anthropic Claude Sonnet 4 (OpenAI GPT-4o fallback); the response is enforced as JSON. Compliance mapping is purely deterministic: each requirement is scored against every ASVS control and PCI-DSS requirement using a relevance function (category match +0.4, keyword overlap +0.1 each, 0.3 retention threshold), with a rationale string for audit defensibility.

Insider-threat mode appends instructions directing the model to additionally generate insider-specific abuse cases (privileged-admin abuse, departing-employee exfiltration, audit-log tampering) and insider-specific requirements (separation of duties, behavioural analytics, privileged access management); each output item carries an `insider_threat` flag. A bidirectional Jira integration publishes analyses back into the originating issue's custom fields, with auto-detection of editable field IDs via the `editmeta` endpoint and graceful fallback from Atlassian Document Format to plain text — so developers see security work-items in the tool they already use.

### 3.3 Continuous Threat-Modelling Pipeline

The threat-modelling component executes a five-stage pipeline. Stage 1 ingests architecture: free-form text, optionally with a diagram image, is parsed by an LLM into structured components, data flows, and trust boundaries, each labelled with `internet_facing`, `handles_sensitive_data`, and `trust_level` flags that drive subsequent risk scoring (`max_tokens=4000`, `temperature=0.3`). Stage 2 — fully deterministic — assembles a *system intelligence context* from sector threat-intelligence (industry-specific actors and TTPs), client-uploaded incident data, the SecureReq abuse cases for this project, and the registered security-control inventory.

Stage 3 generates STRIDE threats in three passes: a deterministic template-based pass (a base-score formula `base = severity_score + 1.0·internet_facing + 0.5·sensitive_data + 0.5·untrusted`), an LLM-enrichment pass on the top 15 critical/high threats (`max_tokens=2000`, supplied with the full system context), and a SecureReq injection pass that imports abuse cases as explicit threats with `source="securereq"` for traceability. Stage 4 enumerates multi-hop attack paths through the data-flow graph, AI-enriches the top five paths with full pen-tester narratives (`max_tokens=3000`), maps each threat to MITRE ATT&CK Tactics and Techniques, builds the seven-phase Lockheed Martin Cyber Kill Chain, and produces hierarchical AND/OR attack trees.

Stage 5 quantifies risk in dollars using FAIR (`ALE = LEF × LM` with industry and organisation-size multipliers and confidence intervals) and generates Mermaid Data Flow Diagrams (always) plus Eraser.io professional diagrams (when an API key is configured).

A defining feature of the pipeline is *stable threat identification*: each threat receives an identifier hashed from (STRIDE category, target component, attack vector). On regeneration after architectural changes, threats are classified as `new`, `existing`, `modified`, or `resolved`, with full diff and timeline views via the `architecture_versions` and `threat_history` tables. Threat modelling thus becomes a *living artefact* rather than a one-time deliverable.

### 3.4 VS Code IDE Extension: Real-Time Shift-Left at the Developer's Keystroke

The VS Code Extension is the leftmost shift-left surface in the platform: security analysis at the developer's keystroke. Implemented as a TypeScript extension and distributed as a `.vsix` package, it runs SAST, Software Composition Analysis (SCA), and secret detection against the active workspace on demand or on save, surfacing findings as native VS Code diagnostics — inline underlines, hover tool-tips, and Problems-panel entries — so vulnerabilities are visible during authorship rather than at code review or CI failure.

A defining property is *rule-corpus identity*: the extension authenticates with a Personal Access Token and consumes the same `custom_rules` table used by the GitHub Commit Monitor and the SAST prioritiser. A finding flagged in the editor is, by construction, identical to the finding that would be raised at commit time — eliminating the *rule-fragmentation problem* whereby IDE linters, CI scanners, and the central platform disagree about whether code is risky. Triage actions (mark resolved, mark false-positive) propagate bidirectionally between the editor and the central platform. An *AI-Suggested Fix* command consumes the shared LLM provider to propose remediation diffs in-line, but the developer must accept the diff before any change is applied — preserving the human-in-the-loop principle.

### 3.5 GitHub Commit Monitor: Behavioural Insider-Threat Detection at Commit Time

Every commit is scored on a 0–10 scale using ten deterministic detector families covering: metadata signals (off-hours commits, author/committer mismatch, unsigned commits, force pushes, large deletions); SAST pattern matching of insider-threat-categorised rules against diff lines; sensitive files (environment files, SSH keys, certificates); binary-file injection (executables, archives, database dumps); dependency tampering (typosquatting, vulnerable version pinning, custom registry URLs, post-install scripts, removal of security packages); CI/CD pipeline tampering (disabled scanners, secret-exfiltration patterns, untrusted Docker base images); configuration weakening (CORS wildcards, MFA disablement, weak TLS, `.gitignore` removal of sensitive patterns); and suspicious commit messages on large changes.

The component additionally maintains a per-developer *behavioural baseline* over a rolling 60-commit window, recording mean and standard deviation of commit hour, mean and 90th-percentile of size metrics, mean historical risk, and weekly commit rate. Baselines reach `partial` status at 5 commits and `established` status at 20. New commits are compared *against the existing baseline first* — anomalies are recorded before the baseline is updated, preventing the observation from contaminating its own reference. Anomaly types include `off_hours_deviation` (z-score ≥ 2.0 medium, ≥ 3.0 high), `large_commit_additions/deletions` (> 5× baseline), and `risk_spike` (> 3× baseline). AI is invoked only on analyst demand, returning a structured JSON threat assessment (`threat_level` ∈ {intentional_insider, suspicious, negligent, false_positive}, `confidence`, `impact_summary`, `intent_analysis`, `malicious_scenario`, `key_indicators`, `recommended_actions`) at `temperature=0.3`. Results are cached per commit.

### 3.6 Cross-Component Integration

The four components are deliberately composable. SecureReq abuse cases are injected as STRIDE threats with `source="securereq"`, providing traceability from product backlog to architectural threat model. The threat model is consumed by a *prioritiser* component that re-ranks SAST findings: matches on internet-facing or untrusted components attract a +1 severity tier, explicit CWE confirmations attract +2 tiers, and findings on trusted internal components with low severity are demoted by 1 tier. Each adjustment is annotated with `rerank_reasons` for analyst transparency. The IDE extension consumes the same rule corpus and false-positive state as the Commit Monitor, so a finding triaged in the editor is suppressed identically at commit time. Conversely, GitHub Monitor findings on components labelled high-risk by the threat model attract higher analyst priority. The platform thus realises a *closed loop* between product, architecture, IDE, and code.

---

## 4. Design Principles: Hybrid, Human-in-the-Loop

Three design principles govern every architectural decision.

**Principle 1 — Determinism first; AI as enrichment.** All authoritative scores (commit risk, threat risk, FAIR ALE, ASVS relevance) are produced by deterministic code. LLMs add narrative enrichment, parsing of unstructured input, and on-demand investigation. They do not assign severities, decide false-positive status, or trigger automated remediation. This preserves reproducibility, audit-defensibility under regulatory scrutiny, and a clear delineation of accountability.

**Principle 2 — Adaptation without fine-tuning.** In place of model fine-tuning, the platform uses an *in-context feedback loop*: analysts submit thumbs-up/thumbs-down ratings on individual abuse cases and security requirements, persisted in a `prompt_feedback` table. The most recent five positive and three negative examples per type are prepended to subsequent prompts as few-shot demonstrations. The model adapts to organisational vocabulary and risk priorities within hours, not training cycles. This pattern is provider-agnostic, transparent, and reversible.

**Principle 3 — Cost and latency under explicit control.** LLM usage is metered by design: SecureReq invokes one call per analysis; the threat-modelling pipeline invokes approximately twenty calls per full generation and zero in *quick mode*; the commit monitor invokes zero calls during routine scanning, with one cached call per analyst-triggered investigation. The IDE extension's AI-fix is also analyst-invoked. Monthly LLM expenditure is therefore bounded and predictable.

These principles operationalise the c0c0n 2026 Chairman's emphasis: *human oversight remains crucial to handle complex attacks and ethical concerns*. The platform's AI surface is large in capability but small in autonomous authority.

---

## 5. Preliminary Evaluation

The platform has been implemented in a working prototype (Python/FastAPI backend, React/TypeScript frontend, SQLite persistence, TypeScript-based VS Code extension, configurable AI provider) totalling approximately twelve thousand lines of backend service code plus the IDE extension across the four components. We report preliminary qualitative observations and structural metrics; a full quantitative evaluation against an annotated insider-threat commit corpus is in progress and will be reported in the camera-ready version.

Structurally, the commit-monitor component implements ten distinct detector families with thirty-plus regex pattern groups; SecureReq's compliance mapper covers all fourteen OWASP ASVS verticals and all twelve PCI-DSS requirement clusters; the threat-modelling pipeline emits STRIDE threats across all six categories with CWE and MITRE ATT&CK technique annotations on every threat. The behavioural-baseline engine produces stable z-score outputs at 20-commit baseline maturity and graceful degradation at the 5-commit `partial` level.

Qualitatively, on small synthetic insider-threat corpora — engineered commits that exfiltrate environment files, comment out CI security scans, introduce typosquatted dependencies, and push at unusual hours — the deterministic detectors achieve true-positive recall consistent with the rule design intent, with false-positives largely confined to legitimate refactors and dependency upgrades that the false-positive workflow can suppress without data loss. The on-demand AI threat assessment produces analyst-grade narrative explanations consistent with the determined risk score.

Three threats to validity are acknowledged: (a) deterministic detector coverage is bounded by the rule corpus, which is a continuously evolving artefact; (b) per-developer baselines require commit-history density that small repositories may not provide; (c) LLM-generated narratives carry residual hallucination risk even in narrative-only roles, mitigated but not eliminated by JSON schema enforcement and `temperature=0.3`.

---

## 6. Discussion and Future Work

The design space has natural extensions. The *stable threat identifier* mechanism applies in principle to any version-aware artefact (Software Bill of Materials diffs, Infrastructure-as-Code change-sets). The per-developer behavioural baseline can be enriched with non-temporal dimensions (file-path entropy, language switching) for a more general behavioural-analytics surface. The in-context feedback loop currently operates at prompt-fragment granularity; a graph-based feedback model could improve adaptation rate.

Ethical considerations are central to insider-threat tooling: per-developer baselining produces personally-identifiable behavioural profiles that demand strict role-based access, retention limits, and disclosure to the workforce. The platform implements role-based read controls and false-positive workflow auditability; formalisation of such controls is itself a research subject.

---

## 7. Conclusion

We have presented the design of an integrated, AI/ML-driven AppSec platform that operationalises insider-threat defence as a continuous, four-stage pipeline spanning stories, architecture, IDE, and commits — a true shift-left from product backlog to running code, unified by a single shared rule corpus. Its defining choices — deterministic scaffolding with LLM enrichment, stable threat identifiers, per-developer behavioural baselines, IDE-resident diagnostics sharing rule and false-positive state with the central scanner, in-context feedback as a fine-tuning substitute, and tight cross-component data flow — collectively realise an *intelligent, adaptive, and predictive* defensive posture that retains the human oversight complex insider scenarios demand. We submit it to c0c0n 2026 as both an engineering result and a position on how AI/ML-driven cyber-defence pipelines should be architected when accountability matters as much as capability.

---

## Indicative References

1. Howard, M. & Lipner, S. *The Security Development Lifecycle.* Microsoft Press, 2006.
2. Jones, J. *An Introduction to Factor Analysis of Information Risk (FAIR).* Risk Management Insight, 2005.
3. The Open Group. *Risk Taxonomy (O-RT) Standard.* 2013.
4. OWASP. *Application Security Verification Standard v4.0.3.* 2024.
5. PCI Security Standards Council. *PCI Data Security Standard v4.0.* 2022.
6. MITRE Corporation. *ATT&CK for Enterprise.* 2024 release.
7. IBM Security. *Cost of a Data Breach Report 2024.*
8. Verizon. *Data Breach Investigations Report 2024.*
9. Hutchins, E. M., Cloppert, M. J., & Amin, R. M. *Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains.* Lockheed Martin, 2011.
10. Shostack, A. *Threat Modeling: Designing for Security.* Wiley, 2014.
