// Reference LSM BPF template for file-access shielding.
// Requires CONFIG_BPF_LSM and a kernel with bpf_lsm hooks enabled.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("lsm/file_open")
int BPF_PROG(aegis_file_open, struct file *file, int ret) {
    // deny write opens on protected paths (simplified; real rules injected)
    return 0; // allow by default
}

char _license[] SEC("license") = "GPL";
