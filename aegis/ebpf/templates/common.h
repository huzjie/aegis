// Shared helpers for aegis-generated eBPF programs.
#ifndef AEGIS_BPF_COMMON_H
#define AEGIS_BPF_COMMON_H

// Stable helper macros usable from any generated program.
#define AEGIS_DENY BPF_DROP
#define AEGIS_ALLOW BPF_OK

#endif // AEGIS_BPF_COMMON_H
