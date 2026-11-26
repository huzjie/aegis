// Reference tc-egress template (see aegis.ebpf.generator for IR -> code).
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tc")
int aegis_egress(struct __sk_buff *skb) {
    return BPF_OK; // placeholder; real program generated from policy
}

char _license[] SEC("license") = "GPL";
