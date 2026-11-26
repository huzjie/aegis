"""eBPF backend: generate a BPF C program + bpftool loader script."""

from aegis.backend.base import Artifact, Backend
from aegis.backend.factory import register
from aegis.ebpf.generator import generate_ebpf_program, generate_loader


@register
class EbpfBackend(Backend):
    name = "ebpf"

    def supports(self, ir: dict) -> bool:
        return any(ir.get(c) for c in ("network", "files", "syscalls", "spawn"))

    def compile(self, ir: dict, policy: dict | None = None) -> Artifact:
        c_source = generate_ebpf_program(ir)
        loader = generate_loader(ir)
        name = ir.get("name", "aegis")
        files = {
            f"{name}.bpf.c": c_source,
            "loader.sh": loader,
        }
        return Artifact(backend=self.name, kind="script", files=files,
                        meta={"build": "clang -O2 -g -target bpf -c program.bpf.c -o program.bpf.o",
                              "load": "sudo ./loader.sh"})
