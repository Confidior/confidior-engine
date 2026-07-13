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


class EdgeType(str, Enum):
    DERIVED_FROM = "derived_from"
    MATCHED_BY = "matched_by"
    PRODUCES = "produces"
    AFFECTS = "affects"
    EVALUATES = "evaluates"
    SUCCESSOR_OF = "successor_of"
    SATISFIES = "satisfies"
    REFERENCES = "references"


TEE_FAIL_BOUNDARY_STATEMENT = (
    "Intel TDX / AMD SEV-SNP threat model excludes physical DRAM interposition. "
    "DDR5 bus interposition demonstrated by TEE.fail research with ~$1,000 hardware. "
    "This evaluation assumes cloud admin and software operator threat models only."
)


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_THRESHOLD = "REQUIRE-THRESHOLD"


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


@dataclass(frozen=True)
class EvidenceNode:
    node_id: str
    node_type: NodeType
    platform: Platform | None = None
    measurement: str | None = None
    debug_disabled: bool | None = None
    tcb_version: str | None = None
    tcb_status: TCBStatus | None = None
    firmware_version: str | None = None
    cve_id: str | None = None
    raw_bytes: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime | None = None
    ttl_seconds: int | None = None
    evidence_type: str | None = None
    claim: str | None = None
    evidence: bytes | None = None
    proof: bytes | None = None
    proof_type: str | None = None
    verifier: str | None = None
    lifecycle_phase: LifecyclePhase | None = None
    data_classification: DataClassification | None = None
    jurisdiction: Jurisdiction | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "platform": self.platform.value if self.platform else None,
            "measurement": self.measurement,
            "debug_disabled": self.debug_disabled,
            "tcb_version": self.tcb_version,
            "tcb_status": self.tcb_status.value if self.tcb_status else None,
            "firmware_version": self.firmware_version,
            "cve_id": self.cve_id,
            "raw_bytes": self.raw_bytes.hex() if self.raw_bytes else None,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "ttl_seconds": self.ttl_seconds,
            "evidence_type": self.evidence_type,
            "claim": self.claim,
            "evidence": self.evidence.hex() if self.evidence else None,
            "proof": self.proof.hex() if self.proof else None,
            "proof_type": self.proof_type,
            "verifier": self.verifier,
            "lifecycle_phase": self.lifecycle_phase.value if self.lifecycle_phase else None,
            "data_classification": self.data_classification.value if self.data_classification else None,
            "jurisdiction": self.jurisdiction.value if self.jurisdiction else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceNode:
        raw = data.get("raw_bytes")
        ev = data.get("evidence")
        pr = data.get("proof")
        return cls(
            node_id=data["node_id"],
            node_type=NodeType(data["node_type"]),
            platform=Platform(data["platform"]) if data.get("platform") else None,
            measurement=data.get("measurement"),
            debug_disabled=data.get("debug_disabled"),
            tcb_version=data.get("tcb_version"),
            tcb_status=TCBStatus(data["tcb_status"]) if data.get("tcb_status") else None,
            firmware_version=data.get("firmware_version"),
            cve_id=data.get("cve_id"),
            raw_bytes=bytes.fromhex(raw) if raw else None,
            metadata=data.get("metadata", {}),
            timestamp=datetime.fromisoformat(data["timestamp"]) if data.get("timestamp") else None,
            ttl_seconds=data.get("ttl_seconds"),
            evidence_type=data.get("evidence_type"),
            claim=data.get("claim"),
            evidence=bytes.fromhex(ev) if ev else None,
            proof=bytes.fromhex(pr) if pr else None,
            proof_type=data.get("proof_type"),
            verifier=data.get("verifier"),
            lifecycle_phase=LifecyclePhase(data["lifecycle_phase"]) if data.get("lifecycle_phase") else None,
            data_classification=DataClassification(data["data_classification"]) if data.get("data_classification") else None,
            jurisdiction=Jurisdiction(data["jurisdiction"]) if data.get("jurisdiction") else None,
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


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    expression: str
    description: str = ""


@dataclass(frozen=True)
class PolicyEvaluation:
    decision: PolicyDecision
    rules_passed: list[str] = field(default_factory=list)
    rules_failed: list[str] = field(default_factory=list)
    rules_not_evaluated: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ComplianceMapping:
    control_id: str
    control_family: ControlFamily
    status: ComplianceStatus
    evidence_node_ids: list[str] = field(default_factory=list)
    gap_description: str | None = None


@dataclass(frozen=True)
class AssuranceEvaluation:
    level: AssuranceLevel
    residual_risk: ResidualRiskTier
    boundary_statement: str
    label: str = ""


@dataclass(frozen=True)
class EvaluationResult:
    policy: PolicyEvaluation
    assurance: AssuranceEvaluation
    compliance_mappings: list[ComplianceMapping] = field(default_factory=list)
    evidence_graph_summary: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime | None = None


@dataclass(frozen=True)
class RekorEntry:
    log_index: int
    log_id: str
    entry_uuid: str
    integrated_time: datetime


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
    evidence_graph_summary: dict[str, Any] = field(default_factory=dict)
    policy_evaluation: PolicyEvaluation | None = None
    assurance: AssuranceEvaluation | None = None
    compliance_mappings: list[ComplianceMapping] = field(default_factory=list)
    secret_release: dict[str, Any] | None = None
    attack_db_snapshot: str | None = None
    signatures: list[Signature] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "timestamp": self.timestamp.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "workload": self.workload,
            "evidence_graph_summary": self.evidence_graph_summary,
            "policy_evaluation": {
                "decision": self.policy_evaluation.decision.value,
                "rules_passed": self.policy_evaluation.rules_passed,
                "rules_failed": self.policy_evaluation.rules_failed,
            } if self.policy_evaluation else None,
            "assurance": {
                "level": self.assurance.level.value,
                "residual_risk": self.assurance.residual_risk.value,
                "boundary_statement": self.assurance.boundary_statement,
                "label": self.assurance.label,
            } if self.assurance else None,
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
                    } if s.rekor_entry else None,
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
            evidence_graph_summary=data.get("evidence_graph_summary", {}),
            policy_evaluation=PolicyEvaluation(
                decision=PolicyDecision(data["policy_evaluation"]["decision"]),
                rules_passed=data["policy_evaluation"].get("rules_passed", []),
                rules_failed=data["policy_evaluation"].get("rules_failed", []),
            ) if data.get("policy_evaluation") else None,
            assurance=AssuranceEvaluation(
                level=AssuranceLevel(data["assurance"]["level"]),
                residual_risk=ResidualRiskTier(data["assurance"]["residual_risk"]),
                boundary_statement=data["assurance"]["boundary_statement"],
                label=data["assurance"].get("label", ""),
            ) if data.get("assurance") else None,
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
                    ) if s.get("rekor_entry") else None,
                )
                for s in data.get("signatures", [])
            ],
        )
