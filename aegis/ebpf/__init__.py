"""eBPF program generation: turn an IR into a BPF C program + loader."""

from aegis.ebpf.generator import generate_ebpf_program, generate_loader

__all__ = ["generate_ebpf_program", "generate_loader"]
