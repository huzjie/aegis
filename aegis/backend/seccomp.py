"""seccomp backend: compile a syscall/spawn deny-list into classic BPF."""

from aegis.backend.base import Artifact, Backend
from aegis.backend.factory import register
from aegis.backend.syscalls import resolve_syscall

# classic BPF opcodes
_BPF_LD = 0x00
_BPF_LDX = 0x01
_BPF_ST = 0x02
_BPF_JMP = 0x05
_BPF_RET = 0x06
_BPF_W = 0x00
_BPF_ABS = 0x20
_BPF_JEQ = 0x10
_BPF_JGE = 0x30
_BPF_K = 0x00
_BPF_JA = 0x00

# seccomp return values (lower 16 bits of the k in RET)
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000

# AUDIT_ARCH_X86_64
_AUDIT_ARCH_X86_64 = 0xC000003E


def _insn(code, jt=0, jf=0, k=0):
    return {"code": code, "jt": jt, "jf": jf, "k": k}


def build_denylist_filter(syscall_numbers: list[int], action_kill: bool = True) -> list:
    """Build a classic-BPF seccomp filter that denies the given syscalls.

    Filter shape::

        ld  arch
        jeq AUDIT_ARCH_X86_64 -> next, else KILL
        (for each denied nr) ld data[0]; jeq nr -> KILL
        RET ALLOW
    """
    insns = []
    insns.append(_insn(_BPF_LD | _BPF_W | _BPF_ABS, k=4))  # A = seccomp_data.arch
    insns.append(_insn(_BPF_JMP | _BPF_JEQ | _BPF_K, jt=1, jf=0, k=_AUDIT_ARCH_X86_64))
    insns.append(_insn(_BPF_RET | _BPF_K, k=_SECCOMP_RET_KILL_PROCESS))
    ret = _SECCOMP_RET_KILL_PROCESS if action_kill else (_SECCOMP_RET_ERRNO | 1)
    for nr in sorted(set(syscall_numbers)):
        insns.append(_insn(_BPF_LD | _BPF_W | _BPF_ABS, k=0))  # A = data[0] = nr
        insns.append(_insn(_BPF_JMP | _BPF_JEQ | _BPF_K, jt=0, jf=1, k=nr))
        insns.append(_insn(_BPF_RET | _BPF_K, k=ret))
    insns.append(_insn(_BPF_RET | _BPF_K, k=_SECCOMP_RET_ALLOW))
    return insns


@register
class SeccompBackend(Backend):
    name = "seccomp"

    def supports(self, ir: dict) -> bool:
        return bool(ir.get("syscalls") or ir.get("spawn"))

    def compile(self, ir: dict, policy: dict | None = None) -> Artifact:
        deny_names = []
        if ir.get("syscalls"):
            deny_names += list(ir["syscalls"].get("deny") or [])
        if ir.get("spawn"):
            deny_names += list(ir["spawn"].get("deny") or [])
        nums = []
        unresolved = []
        for name in deny_names:
            mapped = resolve_syscall(name)
            if name == "*":
                # "*" means deny-all -> represented by allowlist of nothing.
                # fall back to killing everything except a minimal safe set.
                unresolved.append(name)
                continue
            if not mapped:
                unresolved.append(name)
            nums.extend(mapped)
        insns = build_denylist_filter(nums)
        return Artifact(
            backend=self.name, kind="bpf", content=insns,
            meta={"deny_names": deny_names, "syscall_numbers": sorted(set(nums)),
                  "unresolved": unresolved, "arch": "x86_64",
                  "apply": "load with prctl(PR_SET_SECCOMP) / libseccomp; see docs/SECCOMP.md"},
        )

    def apply(self, artifact: Artifact) -> dict:
        return {"backend": self.name, "applied": False,
                "reason": "seccomp apply needs a Linux host (use aegis apply --backend seccomp)"}
