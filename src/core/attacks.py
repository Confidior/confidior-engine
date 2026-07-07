from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from src.core.taxonomy import Platform


class AttackCategory(str, Enum):
    MEMORY_BUS = "memory_bus_interposition"
    ROGUE_MEMORY = "rogue_memory_module"
    PERFORMANCE_COUNTER = "performance_counter_side_channel"
    CHOSEN_PLAINTEXT = "chosen_plaintext_attack"
    INTERRUPT_SIGNAL = "interrupt_signal_ahoi"
    CACHE_SIDE_CHANNEL = "cache_side_channel"
    SPECULATIVE_EXECUTION = "speculative_execution"
    MEMORY_CORRUPTION = "memory_corruption"
    ARCHITECTURAL = "architectural"
    ROWHAMMER = "rowhammer"
    VOLTAGE_MANIPULATION = "voltage_manipulation"
    SYNCHRONIZATION = "synchronization_bug"


class MitigationDifficulty(str, Enum):
    HARDWARE_REDESIGN = "hardware_redesign_required"
    FIRMWARE_PATCH = "firmware_patch_available"
    MICROCODE_UPDATE = "microcode_update_available"
    SOFTWARE_FIX = "software_fix_available"
    NO_MITIGATION = "no_mitigation_available"


@dataclass(frozen=True)
class TEEAttack:
    name: str
    year: int
    affected_platforms: frozenset[Platform]
    category: AttackCategory
    cost_to_attack: str
    impact: str
    mitigation: str
    mitigation_difficulty: MitigationDifficulty
    cve_id: str | None = None
    paper_url: str | None = None
    boundary_statement: str = ""
    patched: bool = False


# Comprehensive TEE attack database from academic literature (2016-2026)
TEE_ATTACKS: list[TEEAttack] = [
    TEEAttack(
        name="TEE.fail",
        year=2025,
        affected_platforms=frozenset({Platform.IntelTDX, Platform.AMDSEVSNP}),
        category=AttackCategory.MEMORY_BUS,
        cost_to_attack="~$1,000",
        impact="Breaks all CC guarantees via DDR5 bus interposition",
        mitigation="Physical DRAM interposition excluded from threat model",
        mitigation_difficulty=MitigationDifficulty.HARDWARE_REDESIGN,
        paper_url="https://www.bleepingcomputer.com/news/security/teefail-attack-breaks-confidential-computing-on-intel-amd-nvidia-cpus/",
        boundary_statement="Intel TDX / AMD SEV-SNP threat model excludes physical DRAM interposition. DDR5 bus interposition demonstrated with ~$1,000 hardware.",
    ),
    TEEAttack(
        name="BadRAM",
        year=2024,
        affected_platforms=frozenset({Platform.AMDSEVSNP}),
        category=AttackCategory.ROGUE_MEMORY,
        cost_to_attack="~$10",
        impact="Bypasses SEV-SNP, fakes attestation, inserts backdoors via rogue SPD chip",
        mitigation="AMD firmware updates to validate SPD metadata at boot",
        mitigation_difficulty=MitigationDifficulty.FIRMWARE_PATCH,
        cve_id="CVE-2024-21944",
        paper_url="https://badram.eu/",
        boundary_statement="BadRAM affects AMD SEV-SNP via rogue SPD chip on DIMM. Intel TDX has alias checking countermeasures. AMD issued firmware patches.",
    ),
    TEEAttack(
        name="Battering RAM",
        year=2025,
        affected_platforms=frozenset({Platform.IntelTDX, Platform.AMDSEVSNP}),
        category=AttackCategory.MEMORY_BUS,
        cost_to_attack="~$50",
        impact="Breaks SGX and SEV-SNP via malicious DRAM interposer",
        mitigation="Physical DRAM interposition excluded from threat model",
        mitigation_difficulty=MitigationDifficulty.HARDWARE_REDESIGN,
        paper_url="https://batteringram.eu",
        boundary_statement="Battering RAM breaks Intel SGX and AMD SEV-SNP with $50 malicious DRAM interposer.",
    ),
    TEEAttack(
        name="WireTap",
        year=2025,
        affected_platforms=frozenset(),
        category=AttackCategory.MEMORY_BUS,
        cost_to_attack="Unknown",
        impact="Breaks Intel SGX via malicious DRAM interposer",
        mitigation="Physical DRAM interposition excluded from threat model",
        mitigation_difficulty=MitigationDifficulty.HARDWARE_REDESIGN,
        paper_url="https://wiretap.fail/",
        boundary_statement="WireTap breaks Intel SGX with malicious DRAM interposer.",
    ),
    TEEAttack(
        name="Heracles",
        year=2025,
        affected_platforms=frozenset({Platform.AMDSEVSNP}),
        category=AttackCategory.CHOSEN_PLAINTEXT,
        cost_to_attack="Unknown",
        impact="Chosen plaintext attack breaks SEV-SNP memory encryption",
        mitigation="Memory encryption redesign required",
        mitigation_difficulty=MitigationDifficulty.HARDWARE_REDESIGN,
        paper_url="https://heracles-attack.github.io/Heracles-CCS2025.pdf",
        boundary_statement="Heracles is a chosen plaintext attack on AMD SEV-SNP that breaks memory encryption.",
    ),
    TEEAttack(
        name="CounterSEVeillance",
        year=2025,
        affected_platforms=frozenset({Platform.AMDSEVSNP}),
        category=AttackCategory.PERFORMANCE_COUNTER,
        cost_to_attack="Unknown",
        impact="Infers secret data from performance counters",
        mitigation="Disable performance counters in TEE; performance impact",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        paper_url="https://www.researchgate.net/publication/390109557_CounterSEVeillance_Performance-Counter_Attacks_on_AMD_SEV-SNP",
        boundary_statement="CounterSEVeillance uses performance counter side-channels on AMD SEV-SNP to infer secret data.",
    ),
    TEEAttack(
        name="Heckler",
        year=2024,
        affected_platforms=frozenset({Platform.IntelTDX, Platform.AMDSEVSNP}),
        category=AttackCategory.INTERRUPT_SIGNAL,
        cost_to_attack="Unknown",
        impact="Ahoi attack exploiting interrupts/signals breaks SEV-SNP and TDX",
        mitigation="Interrupt handling redesign",
        mitigation_difficulty=MitigationDifficulty.MICROCODE_UPDATE,
        paper_url="https://ahoi-attacks.github.io/heckler/",
        boundary_statement="Heckler is an Ahoi attack exploiting interrupts/signals to break AMD SEV-SNP and Intel TDX.",
    ),
    TEEAttack(
        name="WeSee",
        year=2024,
        affected_platforms=frozenset({Platform.AMDSEVSNP}),
        category=AttackCategory.INTERRUPT_SIGNAL,
        cost_to_attack="Unknown",
        impact="Ahoi attack exploiting interrupts/signals breaks SEV-SNP",
        mitigation="Interrupt handling redesign",
        mitigation_difficulty=MitigationDifficulty.MICROCODE_UPDATE,
        paper_url="https://ahoi-attacks.github.io/wesee/",
        boundary_statement="WeSee is an Ahoi attack exploiting interrupts/signals to break AMD SEV-SNP.",
    ),
    TEEAttack(
        name="Sigy",
        year=2024,
        affected_platforms=frozenset(),
        category=AttackCategory.INTERRUPT_SIGNAL,
        cost_to_attack="Unknown",
        impact="Ahoi attack exploiting interrupts/signals breaks SGX",
        mitigation="Interrupt handling redesign",
        mitigation_difficulty=MitigationDifficulty.MICROCODE_UPDATE,
        paper_url="https://ahoi-attacks.github.io/sigy/",
        boundary_statement="Sigy is an Ahoi attack exploiting interrupts/signals to break Intel SGX.",
    ),
    TEEAttack(
        name="MDPeek",
        year=2025,
        affected_platforms=frozenset(),
        category=AttackCategory.CACHE_SIDE_CHANNEL,
        cost_to_attack="Unknown",
        impact="Side-channel attack (MBB) breaks Intel SGX",
        mitigation="Cache partitioning, constant-time code",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        paper_url="https://www.comp.nus.edu.sg/~tcarlson/pdfs/liu2025mbbbiswmdusc.pdf",
        boundary_statement="MDPeek is a side-channel attack on Intel SGX using MBB technique.",
    ),
    TEEAttack(
        name="Downfall",
        year=2023,
        affected_platforms=frozenset(),
        category=AttackCategory.SPECULATIVE_EXECUTION,
        cost_to_attack="Unknown",
        impact="Speculative execution vulnerability breaks Intel SGX",
        mitigation="Microcode updates, compiler barriers; performance impact",
        mitigation_difficulty=MitigationDifficulty.MICROCODE_UPDATE,
        paper_url="https://www.usenix.org/system/files/usenixsecurity23-moghimi.pdf",
        boundary_statement="Downfall is a speculative execution vulnerability affecting Intel SGX.",
    ),
    TEEAttack(
        name="ÆPIC Leak",
        year=2022,
        affected_platforms=frozenset(),
        category=AttackCategory.ARCHITECTURAL,
        cost_to_attack="Unknown",
        impact="Architectural attack exploiting undefined APIC register breaks SGX",
        mitigation="Microcode redesign; fundamental hardware change",
        mitigation_difficulty=MitigationDifficulty.HARDWARE_REDESIGN,
        paper_url="https://aepicleak.com/aepicleak.pdf",
        boundary_statement="ÆPIC Leak is an architectural attack on Intel SGX exploiting undefined APIC register.",
    ),
    TEEAttack(
        name="CacheOut",
        year=2021,
        affected_platforms=frozenset(),
        category=AttackCategory.CACHE_SIDE_CHANNEL,
        cost_to_attack="Unknown",
        impact="MDS side-channel breaks Intel SGX",
        mitigation="Cache partitioning, constant-time code",
        mitigation_difficulty=MitigationDifficulty.MICROCODE_UPDATE,
        paper_url="https://sgaxe.com/files/CacheOut.pdf",
        boundary_statement="CacheOut is an MDS side-channel attack on Intel SGX.",
    ),
    TEEAttack(
        name="CIPHERLEAKs",
        year=2021,
        affected_platforms=frozenset({Platform.AMDSEVSNP}),
        category=AttackCategory.CACHE_SIDE_CHANNEL,
        cost_to_attack="Unknown",
        impact="Side-channel inferring secret register values from VMSA in SEV-SNP",
        mitigation="Cache partitioning, constant-time code",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        paper_url="https://cipherleaks.com/",
        boundary_statement="CIPHERLEAKs infers secret register values from the VM Save Area in AMD SEV-SNP.",
    ),
    TEEAttack(
        name="SGAxe",
        year=2020,
        affected_platforms=frozenset(),
        category=AttackCategory.SPECULATIVE_EXECUTION,
        cost_to_attack="Unknown",
        impact="Transient execution, side-channel breaks Intel SGX",
        mitigation="Microcode updates, compiler barriers",
        mitigation_difficulty=MitigationDifficulty.MICROCODE_UPDATE,
        paper_url="https://sgaxe.com/files/SGAxe.pdf",
        boundary_statement="SGAxe is a transient execution attack on Intel SGX.",
    ),
    TEEAttack(
        name="Plundervolt",
        year=2019,
        affected_platforms=frozenset(),
        category=AttackCategory.VOLTAGE_MANIPULATION,
        cost_to_attack="Unknown",
        impact="Software-based voltage control breaks Intel SGX",
        mitigation="Lock voltage controls; BIOS/firmware fix",
        mitigation_difficulty=MitigationDifficulty.FIRMWARE_PATCH,
        paper_url="https://www.plundervolt.com/",
        boundary_statement="Plundervolt exploits software-exposed energy management mechanisms to break Intel SGX.",
    ),
    TEEAttack(
        name="SEVered",
        year=2019,
        affected_platforms=frozenset({Platform.AMDSEVSNP}),
        category=AttackCategory.MEMORY_BUS,
        cost_to_attack="Unknown",
        impact="Page-remapping attack breaks AMD SEV",
        mitigation="SEV-SNP introduced RMP table to prevent; BadRAM bypasses RMP",
        mitigation_difficulty=MitigationDifficulty.HARDWARE_REDESIGN,
        paper_url="https://arxiv.org/pdf/1805.09604",
        boundary_statement="SEVered is a page-remapping attack on AMD SEV. SEV-SNP introduced RMP table but BadRAM bypasses it.",
    ),
    TEEAttack(
        name="Foreshadow",
        year=2018,
        affected_platforms=frozenset(),
        category=AttackCategory.SPECULATIVE_EXECUTION,
        cost_to_attack="Unknown",
        impact="Spectre variant breaks Intel SGX via side-channel",
        mitigation="Microcode updates, compiler barriers",
        mitigation_difficulty=MitigationDifficulty.MICROCODE_UPDATE,
        paper_url="https://foreshadowattack.eu/foreshadow.pdf",
        boundary_statement="Foreshadow is a Spectre variant that breaks Intel SGX.",
    ),
    TEEAttack(
        name="SGX-ROP",
        year=2022,
        affected_platforms=frozenset(),
        category=AttackCategory.MEMORY_CORRUPTION,
        cost_to_attack="Unknown",
        impact="Enclave malware with ROP fully impersonates host application",
        mitigation="Code hardening, CFI, W^X",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        paper_url="https://arxiv.org/pdf/1902.03256",
        boundary_statement="SGX-ROP demonstrates enclave malware that fully and stealthily impersonates its host application.",
    ),
    TEEAttack(
        name="SGX-Step",
        year=2017,
        affected_platforms=frozenset(),
        category=AttackCategory.CACHE_SIDE_CHANNEL,
        cost_to_attack="Unknown",
        impact="Precise enclave execution control attack framework",
        mitigation="Cache partitioning, constant-time code",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        paper_url="https://vanbulck.net/files/systex17-sgxstep.pdf",
        boundary_statement="SGX-Step provides a practical attack framework for precise enclave execution control.",
    ),
    TEEAttack(
        name="BOOMERANG",
        year=2017,
        affected_platforms=frozenset({Platform.IntelTDX, Platform.AMDSEVSNP}),
        category=AttackCategory.ARCHITECTURAL,
        cost_to_attack="Unknown",
        impact="Confused deputy attack breaks most commercial TEEs",
        mitigation="TEE runtime hardening",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        paper_url="https://sites.cs.ucsb.edu/~vigna/publications/2017_NDSS_Boomerang.pdf",
        boundary_statement="BOOMERANG is a confused deputy attack that breaks most commercial TEE platforms.",
    ),
    TEEAttack(
        name="ARMageddon",
        year=2016,
        affected_platforms=frozenset(),
        category=AttackCategory.CACHE_SIDE_CHANNEL,
        cost_to_attack="Unknown",
        impact="Cross-core cache attacks break ARM TrustZone on Android",
        mitigation="Cache partitioning",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        paper_url="https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_lipp.pdf",
        boundary_statement="ARMageddon breaks ARM TrustZone on default configured Android smartphones via cross-core cache attacks.",
    ),
    TEEAttack(
        name="RMPocalypse",
        year=2025,
        affected_platforms=frozenset({Platform.AMDSEVSNP}),
        category=AttackCategory.MEMORY_CORRUPTION,
        cost_to_attack="Unknown",
        impact="Single 8-byte write corrupts entire RMP (Reverse Map Table), breaking SEV-SNP memory isolation",
        mitigation="RMP table integrity validation required; fundamental SEV-SNP redesign",
        mitigation_difficulty=MitigationDifficulty.HARDWARE_REDESIGN,
        paper_url="https://rmpocalypse.com",
        boundary_statement="RMPocalypse corrupts AMD SEV-SNP's Reverse Map Table with a single 8-byte write, breaking all memory isolation guarantees.",
    ),
    TEEAttack(
        name="VMScape",
        year=2025,
        affected_platforms=frozenset({Platform.AMDSEVSNP, Platform.IntelTDX}),
        category=AttackCategory.ARCHITECTURAL,
        cost_to_attack="Unknown",
        impact="Breaks virtualization boundaries on AMD Zen CPUs and Intel Coffee Lake",
        mitigation="Hypervisor-level isolation hardening; CPU microcode updates",
        mitigation_difficulty=MitigationDifficulty.MICROCODE_UPDATE,
        cve_id="CVE-2025-40300",
        paper_url="https://nvd.nist.gov/vuln/detail/CVE-2025-40300",
        boundary_statement="VMScape (CVE-2025-40300) breaks virtualization boundaries on AMD Zen and Intel Coffee Lake, affecting TEE isolation guarantees.",
    ),
    TEEAttack(
        name="TeeJam",
        year=2024,
        affected_platforms=frozenset(),
        category=AttackCategory.CACHE_SIDE_CHANNEL,
        cost_to_attack="Unknown",
        impact="Sub-cache-line leakage via 4k-aliasing + SGX single-stepping; breaks AES T-Table and recovers 4096-bit RSA keys",
        mitigation="Cache partitioning, constant-time code at sub-cache-line granularity",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        paper_url="https://tches.iacr.org/index.php/TCHES/article/view/11259",
        boundary_statement="TeeJam combines 4k-aliasing with SGX single-stepping to achieve 4-byte intra-cache-line resolution, breaking constant-time crypto implementations.",
    ),
    TEEAttack(
        name="NightVision",
        year=2023,
        affected_platforms=frozenset(),
        category=AttackCategory.CACHE_SIDE_CHANNEL,
        cost_to_attack="Unknown",
        impact="Extracts program counter traces from SGX enclaves, enabling reverse-engineering of private programs",
        mitigation="Code obfuscation, constant control flow, or encrypted enclave code",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        paper_url="https://www.cs.ucr.edu/~trentj/papers/isca23.pdf",
        boundary_statement="NightVision uses non-volatile side-channels to extract dynamic PC traces from SGX enclaves, breaking code confidentiality.",
    ),
    TEEAttack(
        name="VoltJockey",
        year=2019,
        affected_platforms=frozenset(),
        category=AttackCategory.VOLTAGE_MANIPULATION,
        cost_to_attack="Unknown",
        impact="Software-controlled voltage-induced hardware faults break SGX; extracts AES keys and forges RSA signatures",
        mitigation="Lock voltage controls via BIOS/firmware; disable DVFS for untrusted OS",
        mitigation_difficulty=MitigationDifficulty.FIRMWARE_PATCH,
        paper_url="https://ieeexplore.ieee.org/document/9006701/",
        boundary_statement="VoltJockey exploits DVFS to inject voltage-oriented hardware faults into SGX enclaves, completely controlled by software.",
    ),
    TEEAttack(
        name="SGX-Bomb",
        year=2017,
        affected_platforms=frozenset(),
        category=AttackCategory.ROWHAMMER,
        cost_to_attack="Unknown",
        impact="Rowhammer-induced bit flips in enclave memory trigger processor lockdown, causing system-wide DoS",
        mitigation="Rowhammer-free DRAM or TRR; SGX integrity check redesign",
        mitigation_difficulty=MitigationDifficulty.NO_MITIGATION,
        paper_url="https://gts3.org/assets/papers/2017/jang:sgx-bomb.pdf",
        boundary_statement="SGX-Bomb uses Rowhammer to trigger SGX integrity violations, locking the processor and requiring a full system reboot.",
    ),
    TEEAttack(
        name="AsyncShock",
        year=2016,
        affected_platforms=frozenset(),
        category=AttackCategory.SYNCHRONIZATION,
        cost_to_attack="Unknown",
        impact="Exploits UAF and TOCTTOU bugs in multithreaded SGX enclaves via controlled thread scheduling",
        mitigation="Disable multithreading in enclaves or harden synchronization primitives",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        paper_url="https://lsds.doc.ic.ac.uk/sites/default/files/esorics2016%20%281%29.pdf",
        boundary_statement="AsyncShock manipulates SGX enclave thread scheduling to reliably exploit synchronization bugs via segmentation faults.",
    ),
    TEEAttack(
        name="CacheZoom",
        year=2017,
        affected_platforms=frozenset(),
        category=AttackCategory.CACHE_SIDE_CHANNEL,
        cost_to_attack="Unknown",
        impact="L1 Prime+Probe tracks all SGX memory accesses; recovers AES keys with as few as 10 measurements",
        mitigation="Cache partitioning, constant-time code, disable hyperthreading",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        paper_url="https://eprint.iacr.org/2017/618",
        boundary_statement="CacheZoom combines L1 Prime+Probe with OS-level interrupt control to achieve high-resolution side-channel on SGX enclaves.",
    ),
    TEEAttack(
        name="MemJam",
        year=2018,
        affected_platforms=frozenset(),
        category=AttackCategory.CACHE_SIDE_CHANNEL,
        cost_to_attack="Unknown",
        impact="Sub-cache-line timing attack via 4k-aliasing false dependency; breaks constant-time AES in SGX SDK",
        mitigation="Cache partitioning, constant-time code at sub-cache-line granularity",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        paper_url="https://ar5iv.labs.arxiv.org/html/1711.08002",
        boundary_statement="MemJam exploits false read-after-write dependency to create intra-cache-line timing channel against constant-time crypto in SGX.",
    ),
    TEEAttack(
        name="SgxPectre",
        year=2019,
        affected_platforms=frozenset(),
        category=AttackCategory.SPECULATIVE_EXECUTION,
        cost_to_attack="Unknown",
        impact="Spectre variant for SGX; steals seal keys and attestation keys from Intel quoting enclaves",
        mitigation="Microcode updates, compiler barriers (LFENCE), retpoline",
        mitigation_difficulty=MitigationDifficulty.MICROCODE_UPDATE,
        paper_url="https://yinqian.org/papers/eurosp19.pdf",
        boundary_statement="SgxPectre exploits speculative execution to leak enclave secrets including attestation keys, completely defeating SGX confidentiality.",
    ),
    TEEAttack(
        name="Nemesis",
        year=2018,
        affected_platforms=frozenset({Platform.IntelTDX, Platform.AMDSEVSNP}),
        category=AttackCategory.PERFORMANCE_COUNTER,
        cost_to_attack="Unknown",
        impact="Interrupt timing side-channel leaks instruction-granular execution state from SGX and SEV enclaves",
        mitigation="Constant-time interrupt handling; microcode redesign of interrupt latency",
        mitigation_difficulty=MitigationDifficulty.MICROCODE_UPDATE,
        paper_url="https://vanbulck.net/files/ccs18-nemesis.pdf",
        boundary_statement="Nemesis abuses CPU interrupt mechanism to leak microarchitectural instruction timings from hardware-enforced enclaves.",
    ),
    TEEAttack(
        name="CLKscrew",
        year=2017,
        affected_platforms=frozenset(),
        category=AttackCategory.VOLTAGE_MANIPULATION,
        cost_to_attack="Unknown",
        impact="Software-controlled DVFS fault injection breaks ARM TrustZone; extracts AES keys and loads self-signed code",
        mitigation="Lock voltage/frequency controls; security-aware energy management",
        mitigation_difficulty=MitigationDifficulty.FIRMWARE_PATCH,
        paper_url="https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/tang",
        boundary_statement="CLKscrew exploits security-oblivious energy management to inject faults into ARM TrustZone purely from software.",
    ),
    TEEAttack(
        name="Dark-ROP",
        year=2017,
        affected_platforms=frozenset(),
        category=AttackCategory.MEMORY_CORRUPTION,
        cost_to_attack="Unknown",
        impact="ROP attack on encrypted SGX binaries using oracles; exfiltrates enclave code, data, and crypto keys",
        mitigation="Fine-grained ASLR (SGX-Shield), CFI, W^X, reduce TCB",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        paper_url="https://taesoo.kim/pubs/2017/lee:darkrop.pdf",
        boundary_statement="Dark-ROP exploits memory corruption in SGX enclaves via return-oriented programming, completely disarming SGX security guarantees.",
    ),
    TEEAttack(
        name="BunnyHop-Reload",
        year=2023,
        affected_platforms=frozenset(),
        category=AttackCategory.CACHE_SIDE_CHANNEL,
        cost_to_attack="Unknown",
        impact="Branch target buffer attack via instruction prefetcher; breaks elliptic curve secp256k1 in SGX",
        mitigation="BTB isolation, constant-time branch prediction, microcode update",
        mitigation_difficulty=MitigationDifficulty.MICROCODE_UPDATE,
        paper_url="https://www.usenix.org/system/files/usenixsecurity23-zhang-zhiyuan-bunnyhop.pdf",
        boundary_statement="BunnyHop-Reload uses the instruction prefetcher to encode BTB predictions as cache state, enabling Flush+Reload on branch predictor.",
    ),
    TEEAttack(
        name="SEV-Step",
        year=2024,
        affected_platforms=frozenset({Platform.AMDSEVSNP}),
        category=AttackCategory.PERFORMANCE_COUNTER,
        cost_to_attack="Unknown",
        impact="Single-stepping framework for AMD SEV; leaks LUKS2 disk keys and enables Nemesis-style attacks on SEV VMs",
        mitigation="Disable debug API, constant-time code, cache partitioning",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        paper_url="https://tches.iacr.org/index.php/TCHES/article/view/11250",
        boundary_statement="SEV-Step demonstrates that AMD SEV VMs can be reliably single-stepped, enabling the same microarchitectural attacks as SGX-Step.",
    ),
    TEEAttack(
        name="TeeRex",
        year=2020,
        affected_platforms=frozenset(),
        category=AttackCategory.MEMORY_CORRUPTION,
        cost_to_attack="Unknown",
        impact="Automated discovery of memory corruption at host-to-enclave boundary; found vulnerabilities in Intel, Baidu, WolfSSL, Synaptics enclaves",
        mitigation="Strict pointer validation at enclave boundary, symbolic execution testing, reduce TCB",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        paper_url="https://www.usenix.org/conference/usenixsecurity20/presentation/cloosters",
        boundary_statement="TeeRex reveals that exploitable memory corruption vulnerabilities are easily introduced at the SGX host-to-enclave boundary.",
    ),
    # ── ARM CCA attacks ──────────────────────────────────────────────
    TEEAttack(
        name="Devlore",
        year=2024,
        affected_platforms=frozenset({Platform.ARMCCA}),
        category=AttackCategory.INTERRUPT_SIGNAL,
        cost_to_attack="Unknown",
        impact="Device interrupt injection from malicious hypervisor breaks ARM CCA CVM confidentiality and integrity",
        mitigation="Interrupt isolation redesign in Realm Management Monitor (RMM); delegate-but-check strategy",
        mitigation_difficulty=MitigationDifficulty.FIRMWARE_PATCH,
        paper_url="https://arxiv.org/abs/2408.05835",
        boundary_statement="Devlore demonstrates that a malicious hypervisor can inject device interrupts into ARM CCA confidential VMs via the GIC interrupt controller, compromising execution integrity.",
    ),
    TEEAttack(
        name="NanoZone",
        year=2025,
        affected_platforms=frozenset({Platform.ARMCCA}),
        category=AttackCategory.ARCHITECTURAL,
        cost_to_attack="Unknown",
        impact="Intra-VM isolation gap leaves ARM CCA vulnerable to Heartbleed-style bugs and kernel-space privilege escalation within a CVM",
        mitigation="Fine-grained memory protection zones with code-pointer integrity (CPI); ~20% performance overhead",
        mitigation_difficulty=MitigationDifficulty.HARDWARE_REDESIGN,
        paper_url="https://arxiv.org/abs/2506.07034",
        boundary_statement="NanoZone shows ARM CCA isolates at CVM granularity only, leaving intra-VM memory-safety bugs and kernel-space adversaries within a Realm unmitigated.",
    ),
    # ── Apple Private Cloud Compute attacks ─────────────────────────
    TEEAttack(
        name="PCC Path Traversal",
        year=2026,
        affected_platforms=frozenset({Platform.ApplePCC}),
        category=AttackCategory.ARCHITECTURAL,
        cost_to_attack="Unknown",
        impact="Privileged network attacker can leak sensitive user data from Apple PCC nodes via path traversal",
        mitigation="Input validation fixes in PCC Release 5E290.3",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        cve_id="CVE-2026-20685",
        paper_url="https://nvd.nist.gov/vuln/detail/CVE-2026-20685",
        boundary_statement="CVE-2026-20685 is a path traversal vulnerability in Apple Private Cloud Compute allowing a privileged network attacker to leak sensitive request data. Fixed in PCC Release 5E290.3.",
    ),
    TEEAttack(
        name="PCC TGT Validation Bypass",
        year=2026,
        affected_platforms=frozenset({Platform.ApplePCC}),
        category=AttackCategory.ARCHITECTURAL,
        cost_to_attack="Unknown",
        impact="Token validation gap allows forged request tokens; PCC Node does not validate TGT signature despite code existing for it",
        mitigation="Enable TGT signature validation in PCC Node production builds",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        paper_url="https://arxiv.org/abs/2605.24239",
        boundary_statement="Apple PCC Node currently skips TGT (Token Grant Token) signature validation even though the check exists in source code. Attackers still need a valid OTT to exploit.",
    ),
    # ── IBM Secure Execution ─────────────────────────────────────────
    TEEAttack(
        name="IBM SE Boot Image Replay",
        year=2025,
        affected_platforms=frozenset({Platform.IBMSecureExecution}),
        category=AttackCategory.ARCHITECTURAL,
        cost_to_attack="Unknown",
        impact="Replay of signed boot images could bypass Secure Execution integrity guarantees if attestation freshness is not enforced",
        mitigation="Nonce-based attestation freshness, short-lived attestation records",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        paper_url="https://cloud.ibm.com/docs/vpc?topic=vpc-about-attestation",
        boundary_statement="IBM Secure Execution attestation records must include freshness mechanisms (nonce/TTL) to prevent replay of captured boot measurements.",
    ),
    # ── Hygon CSV ────────────────────────────────────────────────────
    TEEAttack(
        name="CSV Cryptographic Primitive Risk",
        year=2025,
        affected_platforms=frozenset({Platform.HygonCSV}),
        category=AttackCategory.ARCHITECTURAL,
        cost_to_attack="Unknown",
        impact="Use of Chinese national cryptographic algorithms (SM2/SM3/SM4) may not be FIPS-compliant or interoperable with global attestation toolchains",
        mitigation="Dual-algorithm support; exportable verification using open-source SMx implementations",
        mitigation_difficulty=MitigationDifficulty.SOFTWARE_FIX,
        paper_url="https://www.alibabacloud.com/blog/openanolis-officially-launches-its-first-csv-confidential-container-solution-with-hygon_599143",
        boundary_statement="Hygon CSV uses Chinese national crypto standards (SM2/SM3/SM4) which differ from the global FIPS/NIST cryptographic baseline. Attestation verification requires SMx algorithm support.",
    ),
]


_DEFAULT_DB_PATH: Path | None = None


def set_attacks_db_path(db_path: str | Path | None) -> None:
    """Set the archaeology DB path for attack queries. ``None`` falls back to the hardcoded list."""
    global _DEFAULT_DB_PATH
    _DEFAULT_DB_PATH = None if db_path is None else Path(db_path)


def _get_attacks_from_db(platform: Platform | None = None, unpatched_only: bool = False) -> list[TEEAttack] | None:
    """Try to load attacks from the archaeology DB. Returns None if DB unavailable."""
    if _DEFAULT_DB_PATH is None:
        return None
    try:
        from src.tools.archaeology import ArchaeologyDB

        db = ArchaeologyDB(db_path=_DEFAULT_DB_PATH)
        records = db.query_attacks(platform=platform)
        db.close()
        result: list[TEEAttack] = []
        for r in records:
            try:
                cat = AttackCategory(r.category)
            except ValueError:
                cat = AttackCategory.MEMORY_BUS
            try:
                diff = MitigationDifficulty(r.mitigation_difficulty)
            except ValueError:
                diff = MitigationDifficulty.NO_MITIGATION
            result.append(TEEAttack(
                name=r.name,
                year=r.year,
                affected_platforms=r.affected_platforms,
                category=cat,
                cost_to_attack=r.cost_to_attack,
                impact=r.impact,
                mitigation=r.mitigation,
                mitigation_difficulty=diff,
                cve_id=r.cve_id,
                paper_url=r.paper_url,
                boundary_statement=r.boundary_statement,
                patched=r.patched,
            ))
        return result
    except Exception:
        return None


def get_attacks_for_platform(platform: Platform) -> list[TEEAttack]:
    """Return all attacks that affect a given platform. Uses DB if available, else hardcoded list."""
    db_attacks = _get_attacks_from_db(platform=platform)
    if db_attacks is not None:
        return db_attacks
    return [a for a in TEE_ATTACKS if platform in a.affected_platforms]


def get_unmitigated_attacks(platform: Platform, firmware_patched: bool = False) -> list[TEEAttack]:
    """Return attacks that affect a platform and have not been mitigated.

    Always excludes attacks flagged ``patched=True`` in the archaeology DB.
    When ``firmware_patched`` is True, additionally excludes attacks whose
    mitigation is a firmware/microcode patch (the legacy heuristic).
    """
    attacks = get_attacks_for_platform(platform)
    attacks = [a for a in attacks if not a.patched]
    if firmware_patched:
        attacks = [a for a in attacks if a.mitigation_difficulty != MitigationDifficulty.FIRMWARE_PATCH]
    return attacks


def compute_attack_db_snapshot() -> str:
    """Return a SHA-256 hash of the current attack database state.

    The hash captures all attack names and their patched status. Any change
    (new attack, status update) produces a different digest, which lets a
    downstream freshness check determine whether an evidence bundle was
    evaluated against a different DB than the current one.
    """
    attacks = _get_attacks_from_db(platform=None)
    if attacks is None:
        attacks = list(TEE_ATTACKS)
    entries = sorted((a.name, a.patched) for a in attacks)
    return hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()


def compute_attack_risk(platforms: set[Platform], firmware_patched: bool = False) -> tuple[str, list[TEEAttack]]:
    """Compute residual risk from TEE attacks.

    Returns:
        Tuple of (risk_statement, list_of_applicable_attacks)
    """
    applicable_attacks: list[TEEAttack] = []
    for platform in platforms:
        applicable_attacks.extend(get_unmitigated_attacks(platform, firmware_patched))

    if not applicable_attacks:
        return "", []

    risk_parts = []
    for attack in applicable_attacks:
        risk_parts.append(
            f"{attack.name} ({attack.year}): {attack.impact} "
            f"[Cost: {attack.cost_to_attack}, Mitigation: {attack.mitigation_difficulty.value}]"
        )

    return "\n".join(risk_parts), applicable_attacks
