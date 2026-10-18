"""Evidence graph data model, node types, platforms, and compliance statuses."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Primitive(str, Enum):
    CC = "CC"
    FHE = "FHE"
    ZK = "ZK"
    MPC = "MPC"
    Hybrid = "Hybrid"


class Platform(str, Enum):
    IntelTDX = "Intel-TDX"
    AMDSEVSNP = "AMD-SEV-SNP"
    AWSNitro = "AWS-Nitro"
    NVIDIAGPUCC = "NVIDIA-GPU-CC"
    OpenTitan = "OpenTitan"
    ApplePCC = "Apple-PCC"
    ARMCCA = "ARM-CCA"
    IBMSecureExecution = "IBM-Secure-Execution"
    HygonCSV = "Hygon-CSV"
    RISCVCoVE = "RISC-V-CoVE"


class LifecyclePhase(str, Enum):
    BUILD_TIME = "build-time"
    BOOT_TIME = "boot-time"
    RUNTIME = "runtime"
    SHUTDOWN = "shutdown"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    RESTRICTED = "restricted"
    CROWN_JEWEL = "crown-jewel"


class ThreatModelTier(str, Enum):
    SOFTWARE_OPERATOR = "software-operator"
    CLOUD_ADMIN = "cloud-admin"
    PHYSICAL_HOST = "physical-host"
    NATION_STATE_PHYSICAL = "nation-state-physical"


class AdversaryPosition(str, Enum):
    """Where an attacker must stand to mount the attack.

    Ordered by increasing capability: an attacker at a lower position cannot
    mount an attack that requires a higher one. Threat models are defined as
    the set of positions they grant, so attack inclusion is derived rather
    than guessed (docs/THREAT-MODELS.md).
    """

    IN_GUEST = "in-guest"
    HOST = "host"
    PHYSICAL = "physical"
    SUPPLY_CHAIN = "supply-chain"


class EvidenceClass(str, Enum):
    """What kind of evidence backs a claim (docs/GRADING.md).

    Provenance order, least to most direct: unknown / point-in-time report /
    vendor-published / vendor-captured / captured / computed golden /
    runtime-anchored. A verdict is only as strong as the weakest class among
    the evidence it rests on.

    This is **one axis**: how the evidence was obtained. It is not a strength
    scale, and the accessor is named ``provenance_rank`` rather than
    ``strength`` for that reason. Evidence can be weak here and decisive in a
    process (a vendor-published auditor's letter), or strong here and
    inadmissible (a computed golden value where a licensed signature is
    required). See ``docs/VERIFIABILITY.md``, "the ladder is self-defeating as
    stated", and the ``standing`` axis it proposes.
    """

    UNKNOWN = "unknown"
    POINT_IN_TIME = "point-in-time"
    VENDOR_PUBLISHED = "vendor-published"
    VENDOR_CAPTURED = "vendor-captured"
    CAPTURED = "captured"
    COMPUTED_GOLDEN = "computed-golden"
    RUNTIME_ANCHORED = "runtime-anchored"

    # The single definition of the ladder order; ``provenance_rank`` and the
    # weakest-link reduction both read it.
    @classmethod
    def provenance_order(cls) -> tuple["EvidenceClass", ...]:
        """The ladder, least to most direct evidence.

        A method rather than a class attribute because any plain class
        attribute on an ``Enum`` is a member, and this is a tuple of members,
        not another one.
        """
        return (
            cls.UNKNOWN,
            cls.POINT_IN_TIME,
            cls.VENDOR_PUBLISHED,
            cls.VENDOR_CAPTURED,
            cls.CAPTURED,
            cls.COMPUTED_GOLDEN,
            cls.RUNTIME_ANCHORED,
        )

    @property
    def provenance_rank(self) -> int:
        """Position on the provenance ladder; higher is more direct evidence.

        This orders *how the evidence was obtained*, which is what the
        weakest-link reduction needs. It is not a claim about how much the
        evidence proves, and it does not rank institutional standing.
        """
        return self.provenance_order().index(self)

    @classmethod
    def from_registry_source(cls, source: str | None) -> "EvidenceClass":
        """Map a measurement-registry ``source`` onto the ladder.

        A fixture is not evidence, so it maps to UNKNOWN: a synthetic value
        tells a reader nothing about the vendor's provenance, and reading it as
        strong is exactly the mistake the ladder exists to prevent.
        """
        if not source:
            return cls.UNKNOWN
        normalised = source.strip().lower()
        if normalised.startswith("synthetic") or normalised in ("fixture", "test"):
            return cls.UNKNOWN
        if "first-capture" in normalised:
            return cls.CAPTURED
        if "vendor-published" in normalised:
            return cls.VENDOR_PUBLISHED
        if "vendor-captured" in normalised:
            return cls.VENDOR_CAPTURED
        if "runtime" in normalised:
            return cls.RUNTIME_ANCHORED
        if "point-in-time" in normalised or "vendor-report" in normalised:
            return cls.POINT_IN_TIME
        if "computed" in normalised:
            return cls.COMPUTED_GOLDEN
        return cls.UNKNOWN

    @classmethod
    def from_registry_entry(cls, entry: dict | None) -> "EvidenceClass":
        """Class for a registry entry; an engine-computed match outweighs source.

        A ``computed-vs-*  MATCH`` verification means the engine derived the
        value itself and it agreed, which is a stronger claim than where the
        comparison value came from.
        """
        if not entry:
            return cls.UNKNOWN
        verification = str(entry.get("verification") or "").lower()
        # "MISMATCH" contains "MATCH", so the disagreement is checked first: a
        # computed value that disagreed with the vendor is a finding, and it
        # does not make the value's provenance any stronger.
        if "mismatch" in verification:
            return cls.from_registry_source(entry.get("source"))
        if "match" in verification and "computed" in verification:
            return cls.COMPUTED_GOLDEN
        return cls.from_registry_source(entry.get("source"))


class ResidualRiskTier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ControlFamily(str, Enum):
    IAM = "IAM"
    CRYPTOGRAPHY = "Cryptography"
    LOGGING = "Logging"
    INFRASTRUCTURE = "Infrastructure"
    DATA_PROTECTION = "Data-Protection"


class TCBStatus(str, Enum):
    CURRENT = "current"
    EXPIRED = "expired"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


class Jurisdiction(str, Enum):
    EU_DE = "EU-DE"
    EU_FR = "EU-FR"
    US = "US"
    SG = "SG"
    IN = "IN"


class AssuranceLevel(int, Enum):
    NONE = 0
    CONFIG_VERIFIED = 1
    HARDWARE_ATTESTED = 2
    OPERATIONAL_ASSURANCE = 3
    DISTRIBUTED_TRUST = 4
    CRYPTOGRAPHIC_PRIVACY = 5


class NodeType(str, Enum):
    QUOTE = "quote"
    MEASUREMENT = "measurement"
    BUILD_PROVENANCE = "build_provenance"
    CLOUD_METADATA = "cloud_metadata"
    TCB_RECORD = "tcb_record"
    CVE_RECORD = "cve_record"
    POLICY_RULE = "policy_rule"
    SECRET_REQUEST = "secret_request"
    IAC_STATE = "iac_state"
    SBOM = "sbom"
    LOG_RECORD = "log_record"
    SECURE_BOOT = "secure_boot"
    IAC_PROVENANCE = "iac_provenance"


class EdgeType(str, Enum):
    DERIVED_FROM = "derived_from"
    MATCHED_BY = "matched_by"
    PRODUCES = "produces"
    AFFECTS = "affects"
    EVALUATES = "evaluates"
    SUCCESSOR_OF = "successor_of"
    SATISFIES = "satisfies"
    REFERENCES = "references"
    #: Two attestations cover the same session, proven by material they both
    #: carry (a challenge, session-key hash or workload digest). Without it, two
    #: quotes say nothing about each other, so platform diversity earns no trust
    #: credit. See docs/GRADING.md and docs/THREAT-MODELS.md.
    BOUND_TO = "bound_to"


TEE_FAIL_BOUNDARY_STATEMENT = (
    "Intel TDX / AMD SEV-SNP threat model excludes physical DRAM interposition. "
    "DDR5 bus interposition demonstrated by TEE.fail research with ~$1,000 hardware. "
    "This evaluation assumes cloud admin and software operator threat models only."
)


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_THRESHOLD = "REQUIRE-THRESHOLD"


#: Version of the bundle JSON shape. Bumped when a key is added, removed or
#: changes meaning, so a reader can tell which shape it is holding before
#: parsing. Mirrors BUNDLE_SCHEMA_VERSION in src/core/identity.py, which is
#: what gets recorded on the bundle; this constant is the one a parser reads.
SCHEMA_VERSION = 1


class PolicyOperator(str, Enum):
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    IN = "IN"


class ComplianceStatus(str, Enum):
    SATISFIED = "SATISFIED"
    PARTIAL = "PARTIAL"
    GAP = "GAP"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class TemporalFreshness(str, Enum):
    """Freshness status of evidence nodes based on age vs TTL."""

    FRESH = "FRESH"
    AGING = "AGING"
    STALE = "STALE"


@dataclass(frozen=True)
class IaCProvenance:
    """Signed in-toto / SLSA provenance statement for a workload artifact."""

    predicate_type: str
    subject_name: str
    subject_digest: dict[str, str]
    signer_identity: str
    slsa_level: int | None = None
    build_commit: str | None = None
    builder_id: str | None = None
    predicate: dict[str, Any] = field(default_factory=dict)
    #: True when the DSSE signature matched a key in the configured trust root,
    #: False when a trusted key rejected it, and None when no trust root was
    #: configured to judge it. ``signer_identity`` is the name the envelope
    #: claims for itself; this is whether anyone was in a position to check it.
    signature_verified: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "predicate_type": self.predicate_type,
            "subject_name": self.subject_name,
            "subject_digest": self.subject_digest,
            "signer_identity": self.signer_identity,
            "slsa_level": self.slsa_level,
            "build_commit": self.build_commit,
            "builder_id": self.builder_id,
            "predicate": self.predicate,
            "signature_verified": self.signature_verified,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IaCProvenance:
        return cls(
            predicate_type=data["predicate_type"],
            subject_name=data["subject_name"],
            subject_digest=data.get("subject_digest", {}),
            signer_identity=data["signer_identity"],
            slsa_level=data.get("slsa_level"),
            build_commit=data.get("build_commit"),
            builder_id=data.get("builder_id"),
            predicate=data.get("predicate", {}),
            signature_verified=data.get("signature_verified"),
        )


@dataclass(frozen=True)
class EvidenceNode:
    node_id: str
    node_type: NodeType
    platform: Platform | None = None
    measurement: str | None = None
    debug_disabled: bool | None = None
    tcb_version: str | None = None
    tcb_status: TCBStatus | None = None
    tcb_level: str | None = None
    tcb_date: str | None = None
    tcb_reference_id: str | None = None
    firmware_version: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    raw_bytes: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime | None = None
    ttl_seconds: int | None = None
    evidence_type: str | None = None
    #: What kind of evidence this node carries (docs/GRADING.md). Set by the
    #: adapter or caller; None scores as the weakest class so an unstated
    #: provenance never reads as strong.
    evidence_class: EvidenceClass | None = None
    claim: str | None = None
    evidence: bytes | None = None
    proof: bytes | None = None
    proof_type: str | None = None
    verifier: str | None = None
    lifecycle_phase: LifecyclePhase | None = None
    data_classification: DataClassification | None = None
    jurisdiction: Jurisdiction | None = None
    iac_provenance: IaCProvenance | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "platform": self.platform.value if self.platform else None,
            "measurement": self.measurement,
            "debug_disabled": self.debug_disabled,
            "tcb_version": self.tcb_version,
            "tcb_status": self.tcb_status.value if self.tcb_status else None,
            "tcb_level": self.tcb_level,
            "tcb_date": self.tcb_date,
            "tcb_reference_id": self.tcb_reference_id,
            "firmware_version": self.firmware_version,
            "cve_ids": list(self.cve_ids),
            "raw_bytes": self.raw_bytes.hex() if self.raw_bytes else None,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "ttl_seconds": self.ttl_seconds,
            "evidence_type": self.evidence_type,
            # The evidence-class ladder is an input to grading, not a display
            # detail: `weakest_evidence_class` reads it to decide how much the
            # verdict may claim. Omitting it meant a graph rebuilt from JSON
            # graded a node as unstated provenance.
            "evidence_class": self.evidence_class.value if self.evidence_class else None,
            "claim": self.claim,
            "evidence": self.evidence.hex() if self.evidence else None,
            "proof": self.proof.hex() if self.proof else None,
            "proof_type": self.proof_type,
            "verifier": self.verifier,
            "lifecycle_phase": self.lifecycle_phase.value if self.lifecycle_phase else None,
            "data_classification": self.data_classification.value
            if self.data_classification
            else None,
            "jurisdiction": self.jurisdiction.value if self.jurisdiction else None,
            "iac_provenance": self.iac_provenance.to_dict() if self.iac_provenance else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceNode:
        raw = data.get("raw_bytes")
        ev = data.get("evidence")
        pr = data.get("proof")
        iac = data.get("iac_provenance")
        return cls(
            node_id=data["node_id"],
            node_type=NodeType(data["node_type"]),
            platform=Platform(data["platform"]) if data.get("platform") else None,
            measurement=data.get("measurement"),
            debug_disabled=data.get("debug_disabled"),
            tcb_version=data.get("tcb_version"),
            tcb_status=TCBStatus(data["tcb_status"]) if data.get("tcb_status") else None,
            tcb_level=data.get("tcb_level"),
            tcb_date=data.get("tcb_date"),
            tcb_reference_id=data.get("tcb_reference_id"),
            firmware_version=data.get("firmware_version"),
            cve_ids=list(data.get("cve_ids") or []),
            raw_bytes=bytes.fromhex(raw) if raw else None,
            metadata=data.get("metadata", {}),
            timestamp=datetime.fromisoformat(data["timestamp"]) if data.get("timestamp") else None,
            ttl_seconds=data.get("ttl_seconds"),
            evidence_type=data.get("evidence_type"),
            evidence_class=(
                EvidenceClass(data["evidence_class"]) if data.get("evidence_class") else None
            ),
            claim=data.get("claim"),
            evidence=bytes.fromhex(ev) if ev else None,
            proof=bytes.fromhex(pr) if pr else None,
            proof_type=data.get("proof_type"),
            verifier=data.get("verifier"),
            lifecycle_phase=LifecyclePhase(data["lifecycle_phase"])
            if data.get("lifecycle_phase")
            else None,
            data_classification=DataClassification(data["data_classification"])
            if data.get("data_classification")
            else None,
            jurisdiction=Jurisdiction(data["jurisdiction"]) if data.get("jurisdiction") else None,
            iac_provenance=IaCProvenance.from_dict(iac) if iac else None,
        )


@dataclass(frozen=True)
class EvidenceEdge:
    source_id: str
    target_id: str
    edge_type: EdgeType


@dataclass
class EvidenceGraph:
    nodes: dict[str, EvidenceNode] = field(default_factory=dict)
    edges: list[EvidenceEdge] = field(default_factory=list)
    #: The challenge the relying party issued for this appraisal, if any. When
    #: set, a cross-platform binding only counts if the quotes answered *this*
    #: challenge. Two quotes sharing a value they both chose prove mutual
    #: binding, which a replayed pair satisfies forever; only a value the
    #: verifier supplied makes the binding fresh. See ``binding.py`` and
    #: ``PRODUCER-SIDE-VERIFICATION.md``.
    expected_challenge: str | None = None

    def add_node(self, node: EvidenceNode) -> None:
        self.nodes[node.node_id] = node

    def add_edge(self, edge: EvidenceEdge) -> None:
        self.edges.append(edge)

    def get_node(self, node_id: str) -> EvidenceNode | None:
        return self.nodes.get(node_id)

    def traverse(self, node_id: str, edge_type: EdgeType | None = None) -> list[EvidenceNode]:
        results = []
        for edge in self.edges:
            if edge.source_id == node_id and (edge_type is None or edge.edge_type == edge_type):
                target = self.nodes.get(edge.target_id)
                if target:
                    results.append(target)
        return results

    def nodes_by_type(self, node_type: NodeType) -> list[EvidenceNode]:
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def nodes_by_platform(self, platform: Platform) -> list[EvidenceNode]:
        return [n for n in self.nodes.values() if n.platform == platform]

    def incoming_edges(self, node_id: str) -> list[EvidenceEdge]:
        return [e for e in self.edges if e.target_id == node_id]

    def edges_of_type(self, edge_type: EdgeType) -> list[EvidenceEdge]:
        return [e for e in self.edges if e.edge_type == edge_type]

    def subgraph(self, node_ids: set[str]) -> EvidenceGraph:
        nodes = {nid: self.nodes[nid] for nid in node_ids if nid in self.nodes}
        edge_ids = set(node_ids)
        edges = [e for e in self.edges if e.source_id in edge_ids and e.target_id in edge_ids]
        return EvidenceGraph(nodes=nodes, edges=edges)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": {nid: node.to_dict() for nid, node in self.nodes.items()},
            "edges": [
                {
                    "source_id": e.source_id,
                    "target_id": e.target_id,
                    "edge_type": e.edge_type.value,
                }
                for e in self.edges
            ],
            **({"expected_challenge": self.expected_challenge} if self.expected_challenge else {}),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceGraph:
        nodes = {nid: EvidenceNode.from_dict(ndata) for nid, ndata in data.get("nodes", {}).items()}
        edges = [
            EvidenceEdge(
                source_id=e["source_id"],
                target_id=e["target_id"],
                edge_type=EdgeType(e["edge_type"]),
            )
            for e in data.get("edges", [])
        ]
        return cls(
            nodes=nodes,
            edges=edges,
            expected_challenge=data.get("expected_challenge"),
        )


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    expression: str
    description: str = ""
    #: How much the rule counts toward policy conformance: high 3, medium 2,
    #: low 1. Declared in the policy's ``rule_meta`` document.
    severity: str = "medium"


@dataclass(frozen=True)
class PolicyEvaluation:
    decision: PolicyDecision
    rules_passed: list[str] = field(default_factory=list)
    rules_failed: list[str] = field(default_factory=list)
    rules_not_evaluated: list[str] = field(default_factory=list)
    #: Rule id to the reasons it failed, as the rule itself reported them. A
    #: failed rule that explained nothing is absent; the id in ``rules_failed``
    #: is what says it failed.
    findings: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class ComplianceMapping:
    control_id: str
    control_family: ControlFamily
    status: ComplianceStatus
    evidence_node_ids: list[str] = field(default_factory=list)
    gap_description: str | None = None
    attack_id: str | None = None


@dataclass(frozen=True)
class ScoreProfile:
    """Configurable weights and grade thresholds for numeric scoring."""

    name: str
    weights: dict[str, int]
    grade_thresholds: dict[str, int]


class ReferenceRole(str, Enum):
    """Why an artifact is named in a bundle (docs/ARTIFACT-IDENTITY.md).

    The role is the reason the artifact is present, which is what lets a reader
    reconstruct the derivation: which engine, applied which rubric, with which
    weights, under which policy, to which input, producing which output.
    """

    ENGINE = "engine"
    SCHEMA = "schema"
    WEIGHTS = "weights"
    RUBRIC = "rubric"
    POLICY = "policy"
    KNOWLEDGE_BASE = "knowledge_base"
    INPUT = "input"
    OUTPUT = "output"


@dataclass(frozen=True)
class Reference:
    """A named, content-addressed artifact the verdict derives from.

    The hash is the identity; the id is a human label. Where the two disagree,
    the hash wins. A reference must resolve, inline, by a published location,
    or through a registry, or it is a defect (docs/ARTIFACT-IDENTITY.md).

    ``location`` is the published path (repository-relative), present when the
    artifact is fetchable. ``id`` carries ``label@sha256:<hash>`` for artifacts
    the commitments file already publishes, and a bare identifier (a profile
    name, a workload name) when the hash is computed by the engine.
    """

    role: ReferenceRole
    id: str
    hash: str = ""
    location: str = ""
    inline: str = ""

    def resolves_to(self) -> str:
        """Where a reader can get the bytes: ``inline``, ``location`` or hash."""
        if self.inline:
            return "inline"
        if self.location:
            return "published"
        return "hash-only"

    def to_dict(self) -> dict[str, str]:
        # Omit empty fields so a reader never has to distinguish "absent" from
        # "present but empty" when deciding whether a reference resolves.
        out = {"role": self.role.value, "id": self.id}
        if self.hash:
            out["hash"] = self.hash
        if self.location:
            out["location"] = self.location
        if self.inline:
            out["inline"] = self.inline
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Reference":
        return cls(
            role=ReferenceRole(data["role"]),
            id=data.get("id", ""),
            hash=data.get("hash", ""),
            location=data.get("location", ""),
            inline=data.get("inline", ""),
        )


@dataclass(frozen=True)
class ScoringAttack:
    """An attack that counted against the threat subscore, as scored.

    Kept on the result so every display surface (badge, report, explain) reads
    the same arithmetic instead of re-deriving it: which attacks applied under
    the threat model, where the attacker must stand for each, how much of it
    remains unmitigated, and what it cost in points.
    """

    name: str
    position: str
    coverage: float
    penalty: int
    cve_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScoreResult:
    """Numeric composite score (0-100) with per-dimension subscores.

    platform_score and quote_score split the total into the platform's
    inherent attack surface (threat + compliance, derived from the attack
    DB) and this quote's specific state (attestation + trust + freshness).
    """

    total: int
    subscores: dict[str, int]
    grade: str = ""
    profile: str = "default"
    platform_score: int | None = None
    quote_score: int | None = None
    #: Severity-weighted share of the policy the evidence satisfies
    #: (satisfied/failed/not_evaluated/total/ratio and rule counts), or None
    #: when no policy was evaluated. Drives the ``compliance`` subscore, which
    #: measures policy conformance. See docs/GRADING.md.
    policy_conformance: dict | None = None
    #: The weakest evidence class backing the verdict (docs/GRADING.md); the
    #: verdict is only as strong as its weakest input.
    evidence_class: "EvidenceClass | None" = None
    #: Attacks that counted against the threat subscore and what each cost, so
    #: the grade can be argued with line by line. Empty when nothing applied.
    scoring_attacks: tuple["ScoringAttack", ...] = ()
    #: Distinct platforms among the quote nodes, and whether those attestations
    #: are bound to a shared session. A second platform earns trust credit only
    #: when it is bound; an unbound one is reported without credit.
    platform_count: int = 0
    platforms_bound: bool = False


@dataclass(frozen=True)
class AssuranceEvaluation:
    level: AssuranceLevel
    residual_risk: ResidualRiskTier
    boundary_statement: str
    label: str = ""
    temporal_freshness: TemporalFreshness | None = None
    dimensions: dict[str, str] = field(default_factory=dict)
    score: ScoreResult | None = None
    score_profile: str = "default"
    #: Semantic identity of the threat scope this evaluation was made under:
    #: ``"cloud-admin"`` for a preset, ``"custom:<sha256>"`` for a user-defined
    #: one. It changes the grade (the same evidence grades differently under
    #: ``cloud-admin`` and ``physical-host``), so a verdict that omits it is not
    #: reproducible. A name alone is insufficient: a custom scope's name is
    #: user-chosen, and two scopes can share a label and select different attack
    #: sets. See ``threat_scope.scope_identity``.
    threat_model: str = ""
    #: The full replayable scope: label, kind, granted positions and included
    #: categories. Enough to reconstruct the attack set without the file the
    #: scope came from, which is what makes a stored verdict re-gradable.
    threat_scope: dict[str, Any] = field(default_factory=dict)
    #: Machine-readable constraints the verdict rests on, as distinct from the
    #: prose ``boundary_statement``. A boundary statement is what the verdict
    #: *does not* claim, and it is a first-class part of the verdict rather than
    #: commentary on it: the same grade under a wider scope means something
    #: different, and a reader must be able to check which attacks were counted
    #: versus merely known. Prose is for humans; this is for whatever re-grades
    #: or renders the verdict. Shapes:
    #:
    #: - ``attacks_in_scope`` / ``attacks_known``: how much of the known corpus
    #:   the grade actually used
    #: - ``attacks_excluded_by_scope``: named, so narrowing stays visible
    #: - ``assumptions``: standing exclusions (e.g. physical DRAM interposition)
    boundary_constraints: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvaluationResult:
    policy: PolicyEvaluation
    assurance: AssuranceEvaluation
    compliance_mappings: list[ComplianceMapping] = field(default_factory=list)
    evidence_graph_summary: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime | None = None


@dataclass(frozen=True)
class RekorEntry:
    """An entry in the Rekor transparency log, plus what makes it checkable.

    ``inclusion_proof`` and ``checkpoint`` carry the material a reader needs to
    re-verify the anchor without trusting this engine (docs/INTEGRATION-ROADMAP.md,
    SCITT alignment): the audit path proves the entry is in the tree the log
    named, and the signed checkpoint is the log's statement of that tree's root.

    Both default empty, so a bundle anchored before this existed still loads and
    simply reads as "no proof recorded" rather than as verified.
    """

    log_index: int
    log_id: str
    entry_uuid: str
    integrated_time: datetime
    #: The entry's base64 body, which is the leaf preimage the inclusion proof is
    #: over. Without it the proof cannot be checked at all: the audit path proves
    #: nothing unless the reader can hash the thing that was anchored.
    body: str = ""
    #: RFC 9162 inclusion proof, as Rekor returned it. Its ``hashes`` and
    #: ``rootHash`` are hex, not base64. Empty when the log returned none.
    inclusion_proof: dict[str, Any] = field(default_factory=dict)
    #: The log's signed checkpoint (a C2SP signed note) covering that root.
    checkpoint: str = ""


@dataclass(frozen=True)
class Signature:
    key_id: str
    algorithm: str
    signature_hex: str
    rekor_entry: RekorEntry | None = None


@dataclass
class EvidenceBundle:
    bundle_id: str
    timestamp: datetime
    expires_at: datetime
    workload: str
    platform: str = ""
    evidence_graph_summary: dict[str, Any] = field(default_factory=dict)
    policy_evaluation: PolicyEvaluation | None = None
    assurance: AssuranceEvaluation | None = None
    compliance_mappings: list[ComplianceMapping] = field(default_factory=list)
    secret_release: dict[str, Any] | None = None
    attack_db_snapshot: str | None = None
    dimensions: dict[str, str] = field(default_factory=dict)
    signatures: list[Signature] = field(default_factory=list)
    # Version manifest: what produced this verdict. An empty string means the
    # value was never recorded, which is the case for bundles signed before the
    # manifest existed. Those cannot be re-derived. Populated by
    # create_signed_bundle from src.core.identity.bundle_manifest.
    engine_version: str = ""
    schema_version: str = ""
    weight_profile: str = ""
    policy_version: str = ""
    rubric_version: str = ""
    knowledge_base_version: str = ""
    #: The derivation list: every artifact this verdict derives from, named by
    #: role and content hash (docs/ARTIFACT-IDENTITY.md). Inside the signed
    #: payload, so the signature covers what produced the verdict and not only
    #: the verdict. Empty for bundles signed before this existed.
    references: list[Reference] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "timestamp": self.timestamp.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "workload": self.workload,
            "platform": self.platform,
            "engine_version": self.engine_version,
            "schema_version": self.schema_version,
            "weight_profile": self.weight_profile,
            "policy_version": self.policy_version,
            "rubric_version": self.rubric_version,
            "knowledge_base_version": self.knowledge_base_version,
            "references": [r.to_dict() for r in self.references],
            "evidence_graph_summary": self.evidence_graph_summary,
            "policy_evaluation": {
                "decision": self.policy_evaluation.decision.value,
                "rules_passed": self.policy_evaluation.rules_passed,
                "rules_failed": self.policy_evaluation.rules_failed,
                # Not-evaluated is a third outcome, not the absence of the other
                # two: a rule that could not be applied because the evidence did
                # not speak to it must not be stored as if it had passed.
                "rules_not_evaluated": self.policy_evaluation.rules_not_evaluated,
                # Why a rule failed, in the rule's own words. The ids alone
                # tell a reader which rules did not hold; this tells them what
                # the evidence actually looked like.
                "findings": self.policy_evaluation.findings,
            }
            if self.policy_evaluation
            else None,
            "assurance": {
                "level": self.assurance.level.value,
                "residual_risk": self.assurance.residual_risk.value,
                "boundary_statement": self.assurance.boundary_statement,
                "label": self.assurance.label,
                # The temporal model is a computed signal, not a decoration: an
                # attestation that was fresh when it was graded and is stale now is
                # a different finding. Omitting it here made a reloaded bundle say
                # nothing about freshness while the live run knew.
                "temporal_freshness": self.assurance.temporal_freshness,
                "dimensions": dict(self.assurance.dimensions),
                "score": {
                    "total": self.assurance.score.total,
                    "subscores": dict(self.assurance.score.subscores),
                    "grade": self.assurance.score.grade,
                    "profile": self.assurance.score.profile,
                    # These four are rendered by every display surface. Dropping
                    # them made a reloaded bundle read "none applied" for attacks
                    # and lose the platform/quote split and the evidence class,
                    # while the live run showed all three.
                    "platform_score": self.assurance.score.platform_score,
                    "quote_score": self.assurance.score.quote_score,
                    "evidence_class": (
                        self.assurance.score.evidence_class.value
                        if self.assurance.score.evidence_class
                        else None
                    ),
                    "scoring_attacks": [
                        {
                            "name": a.name,
                            "position": a.position,
                            "coverage": a.coverage,
                            "penalty": a.penalty,
                            "cve_ids": list(a.cve_ids),
                        }
                        for a in self.assurance.score.scoring_attacks
                    ],
                    "platform_count": self.assurance.score.platform_count,
                    "platforms_bound": self.assurance.score.platforms_bound,
                    "policy_conformance": self.assurance.score.policy_conformance,
                }
                if self.assurance.score
                else None,
                "score_profile": self.assurance.score_profile,
                "threat_model": self.assurance.threat_model,
                "threat_scope": dict(self.assurance.threat_scope),
                "boundary_constraints": dict(self.assurance.boundary_constraints),
            }
            if self.assurance
            else None,
            "compliance_mappings": [
                {
                    "control_id": m.control_id,
                    "control_family": m.control_family.value,
                    "status": m.status.value,
                    "evidence_node_ids": m.evidence_node_ids,
                    "gap_description": m.gap_description,
                }
                for m in self.compliance_mappings
            ],
            "secret_release": self.secret_release,
            "attack_db_snapshot": self.attack_db_snapshot,
            "dimensions": dict(self.dimensions),
            "signatures": [
                {
                    "key_id": s.key_id,
                    "algorithm": s.algorithm,
                    "signature_hex": s.signature_hex,
                    "rekor_entry": {
                        "log_index": s.rekor_entry.log_index,
                        "log_id": s.rekor_entry.log_id,
                        "entry_uuid": s.rekor_entry.entry_uuid,
                        "integrated_time": s.rekor_entry.integrated_time.isoformat(),
                        # Optional in the schema: a bundle anchored before these
                        # existed still round-trips, and reads as no proof.
                        **(
                            {
                                "body": s.rekor_entry.body,
                                "inclusion_proof": s.rekor_entry.inclusion_proof,
                                "checkpoint": s.rekor_entry.checkpoint,
                            }
                            if s.rekor_entry.inclusion_proof or s.rekor_entry.checkpoint
                            else {}
                        ),
                    }
                    if s.rekor_entry
                    else None,
                }
                for s in self.signatures
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceBundle:
        return cls(
            bundle_id=data["bundle_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            workload=data["workload"],
            platform=data.get("platform", ""),
            evidence_graph_summary=data.get("evidence_graph_summary", {}),
            policy_evaluation=PolicyEvaluation(
                decision=PolicyDecision(data["policy_evaluation"]["decision"]),
                rules_passed=data["policy_evaluation"].get("rules_passed", []),
                rules_failed=data["policy_evaluation"].get("rules_failed", []),
                rules_not_evaluated=data["policy_evaluation"].get("rules_not_evaluated", []),
                findings=data["policy_evaluation"].get("findings", {}),
            )
            if data.get("policy_evaluation")
            else None,
            assurance=AssuranceEvaluation(
                level=AssuranceLevel(data["assurance"]["level"]),
                residual_risk=ResidualRiskTier(data["assurance"]["residual_risk"]),
                boundary_statement=data["assurance"]["boundary_statement"],
                label=data["assurance"].get("label", ""),
                temporal_freshness=data["assurance"].get("temporal_freshness"),
                dimensions=data["assurance"].get("dimensions", {}),
                score=ScoreResult(
                    total=data["assurance"]["score"]["total"],
                    subscores=data["assurance"]["score"].get("subscores", {}),
                    grade=data["assurance"]["score"].get("grade", ""),
                    profile=data["assurance"]["score"].get("profile", "default"),
                    platform_score=data["assurance"]["score"].get("platform_score"),
                    quote_score=data["assurance"]["score"].get("quote_score"),
                    evidence_class=(
                        EvidenceClass(data["assurance"]["score"]["evidence_class"])
                        if data["assurance"]["score"].get("evidence_class")
                        else None
                    ),
                    scoring_attacks=tuple(
                        ScoringAttack(
                            name=a["name"],
                            position=a.get("position", ""),
                            coverage=a.get("coverage", 1.0),
                            penalty=a.get("penalty", 0),
                            cve_ids=tuple(a.get("cve_ids", [])),
                        )
                        for a in data["assurance"]["score"].get("scoring_attacks", [])
                    ),
                    platform_count=data["assurance"]["score"].get("platform_count", 0),
                    platforms_bound=data["assurance"]["score"].get("platforms_bound", False),
                    policy_conformance=data["assurance"]["score"].get("policy_conformance"),
                )
                if data["assurance"].get("score")
                else None,
                score_profile=data["assurance"].get("score_profile", "default"),
                threat_model=data["assurance"].get("threat_model", ""),
                threat_scope=dict(data["assurance"].get("threat_scope") or {}),
                boundary_constraints=dict(
                    data["assurance"].get("boundary_constraints") or {}
                ),
            )
            if data.get("assurance")
            else None,
            compliance_mappings=[
                ComplianceMapping(
                    control_id=m["control_id"],
                    control_family=ControlFamily(m.get("control_family", "IAM")),
                    status=ComplianceStatus(m["status"]),
                    evidence_node_ids=m.get("evidence_node_ids", []),
                    gap_description=m.get("gap_description"),
                )
                for m in data.get("compliance_mappings", [])
            ],
            secret_release=data.get("secret_release"),
            attack_db_snapshot=data.get("attack_db_snapshot"),
            dimensions=data.get("dimensions", {}),
            engine_version=data.get("engine_version", ""),
            schema_version=data.get("schema_version", ""),
            weight_profile=data.get("weight_profile", ""),
            policy_version=data.get("policy_version", ""),
            rubric_version=data.get("rubric_version", ""),
            knowledge_base_version=data.get("knowledge_base_version", ""),
            references=[Reference.from_dict(r) for r in data.get("references", [])],
            signatures=[
                Signature(
                    key_id=s["key_id"],
                    algorithm=s["algorithm"],
                    signature_hex=s["signature_hex"],
                    rekor_entry=RekorEntry(
                        log_index=s["rekor_entry"]["log_index"],
                        log_id=s["rekor_entry"]["log_id"],
                        entry_uuid=s["rekor_entry"]["entry_uuid"],
                        integrated_time=datetime.fromisoformat(s["rekor_entry"]["integrated_time"]),
                        body=s["rekor_entry"].get("body", ""),
                        inclusion_proof=s["rekor_entry"].get("inclusion_proof", {}),
                        checkpoint=s["rekor_entry"].get("checkpoint", ""),
                    )
                    if s.get("rekor_entry")
                    else None,
                )
                for s in data.get("signatures", [])
            ],
        )
