// SPECTRE v10.0 Rust Kubernetes Admission, Pod Security & eBPF SecurityContext Auditor (ABI v1000)
// SPDX-License-Identifier: Apache-2.0
// Audits multi-document Kubernetes YAML manifests for:
//   1. Fail-open Admission Webhooks (`failurePolicy: Ignore` -> CWE-636)
//   2. Privileged pods, hostPID/hostNetwork/hostIPC & sensitive hostPath mounts (`CWE-250`)
//   3. Unguarded eBPF/kernel capabilities (`BPF`, `SYS_ADMIN`, `PERFMON`, `SYS_PTRACE`, `SYS_MODULE`)
//      when `seccompProfile: RuntimeDefault/Localhost` isolation is missing (`CWE-250`)

fn json_esc_k8s(raw: &str) -> String {
    let mut s = String::with_capacity(raw.len() + 4);
    for ch in raw.chars() {
        match ch {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' | '\r' | '\t' => s.push(' '),
            c if (c as u32) >= 0x20 => s.push(c),
            _ => {}
        }
    }
    s
}

fn split_yaml_docs_with_offset(src: &str) -> Vec<(usize, &str)> {
    let mut docs: Vec<(usize, &str)> = Vec::new();
    let mut start_byte = 0usize;
    let mut start_line = 1usize;
    let mut cur_line = 1usize;
    let mut idx = 0usize;
    for raw_ln in src.split_inclusive('\n') {
        let trimmed = raw_ln.trim();
        if trimmed == "---" || trimmed == "..." {
            if idx > start_byte {
                docs.push((start_line, &src[start_byte..idx]));
            }
            start_byte = idx + raw_ln.len();
            start_line = cur_line + 1;
        }
        idx += raw_ln.len();
        cur_line += 1;
    }
    if start_byte < src.len() {
        docs.push((start_line, &src[start_byte..]));
    }
    docs
}

pub fn audit_k8s_posture_json(yaml_src: &str) -> String {
    let mut findings: Vec<String> = Vec::new();
    let sensitive_mounts = [
        "/var/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/etc/kubernetes",
        "/var/lib/kubelet",
        "/proc",
        "/sys",
    ];
    let kernel_ebpf_caps = ["BPF", "SYS_ADMIN", "PERFMON", "SYS_PTRACE", "SYS_MODULE"];

    for (base_line, doc) in split_yaml_docs_with_offset(yaml_src) {
        let mut kind = "";
        let mut meta_name = "default-workload";
        let mut has_seccomp = false;
        let mut priv_line = 0usize;
        let mut host_ns_line = 0usize;
        let mut host_ns_flag = "";
        let mut host_path_line = 0usize;
        let mut host_path_val = "";
        let mut fail_open_line = 0usize;
        let mut ebpf_cap_line = 0usize;
        let mut ebpf_cap_name = "";
        let mut in_caps_add = false;
        let mut add_indent = 0usize;

        for (offset, raw_ln) in doc.lines().enumerate() {
            let lno = base_line + offset;
            let trimmed = raw_ln.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let indent = raw_ln.len() - raw_ln.trim_start().len();
            if in_caps_add && indent <= add_indent && !trimmed.starts_with('-') {
                in_caps_add = false;
            }
            if let Some(rest) = trimmed.strip_prefix("kind:") {
                kind = rest.trim().trim_matches(|c| c == '"' || c == '\'');
            } else if indent <= 4 {
                if let Some(rest) = trimmed.strip_prefix("name:") {
                    let cand = rest.trim().trim_matches(|c| c == '"' || c == '\'');
                    if !cand.is_empty() && meta_name == "default-workload" {
                        meta_name = cand;
                    }
                }
            }
            if let Some(tv_r) = trimmed.strip_prefix("type:") {
                let tv = tv_r.trim().trim_matches(|c| c == '"' || c == '\'');
                if tv == "RuntimeDefault" || tv == "Localhost" {
                    has_seccomp = true;
                }
            }
            if trimmed == "privileged: true" && priv_line == 0 {
                priv_line = lno;
            }
            if host_ns_line == 0 {
                for ns_key in &["hostPID: true", "hostNetwork: true", "hostIPC: true"] {
                    if trimmed == *ns_key {
                        host_ns_line = lno;
                        host_ns_flag = ns_key;
                        break;
                    }
                }
            }
            if let Some(p_rest) = trimmed.strip_prefix("path:") {
                let pv = p_rest.trim().trim_matches(|c| c == '"' || c == '\'');
                if host_path_line == 0 {
                    for sm in &sensitive_mounts {
                        if pv == *sm || pv.starts_with(&format!("{}/", sm)) {
                            host_path_line = lno;
                            host_path_val = pv;
                            break;
                        }
                    }
                }
            }
            if let Some(fp_rest) = trimmed.strip_prefix("failurePolicy:") {
                let fpv = fp_rest.trim().trim_matches(|c| c == '"' || c == '\'');
                if fpv.eq_ignore_ascii_case("Ignore") && fail_open_line == 0 {
                    fail_open_line = lno;
                }
            }
            if trimmed.starts_with("add:") {
                in_caps_add = true;
                add_indent = indent;
                let inline_caps = trimmed[4..].trim();
                for cap in &kernel_ebpf_caps {
                    if inline_caps.contains(cap) && ebpf_cap_line == 0 {
                        ebpf_cap_line = lno;
                        ebpf_cap_name = cap;
                    }
                }
            } else if in_caps_add && trimmed.starts_with('-') {
                let item = trimmed.trim_start_matches('-').trim().trim_matches(|c| c == '"' || c == '\'');
                let norm = item.strip_prefix("CAP_").unwrap_or(item);
                for cap in &kernel_ebpf_caps {
                    if norm == *cap && ebpf_cap_line == 0 {
                        ebpf_cap_line = lno;
                        ebpf_cap_name = cap;
                    }
                }
            }
        }

        let is_webhook = kind == "ValidatingWebhookConfiguration" || kind == "MutatingWebhookConfiguration";
        let is_workload = matches!(
            kind,
            "Pod" | "Deployment" | "DaemonSet" | "StatefulSet" | "ReplicaSet" | "Job" | "CronJob"
        );

        if is_webhook && fail_open_line > 0 {
            findings.push(format!(
                "{{\"line\":{},\"cwe\":\"CWE-636\",\"severity\":\"High\",\"kind\":\"{}\",\"name\":\"{}\",\"rule\":\"K8S_WEBHOOK_FAIL_OPEN\",\"detail\":\"Admission webhook sets failurePolicy: Ignore\"}}",
                fail_open_line, json_esc_k8s(kind), json_esc_k8s(meta_name)
            ));
        }
        if is_workload && priv_line > 0 {
            findings.push(format!(
                "{{\"line\":{},\"cwe\":\"CWE-250\",\"severity\":\"Critical\",\"kind\":\"{}\",\"name\":\"{}\",\"rule\":\"K8S_PRIVILEGED_CONTAINER\",\"detail\":\"Workload enables securityContext.privileged: true\"}}",
                priv_line, json_esc_k8s(kind), json_esc_k8s(meta_name)
            ));
        }
        if is_workload && host_ns_line > 0 {
            findings.push(format!(
                "{{\"line\":{},\"cwe\":\"CWE-250\",\"severity\":\"High\",\"kind\":\"{}\",\"name\":\"{}\",\"rule\":\"K8S_HOST_NAMESPACE_SHARING\",\"detail\":\"Workload shares host namespace ({})\"}}",
                host_ns_line, json_esc_k8s(kind), json_esc_k8s(meta_name), json_esc_k8s(host_ns_flag)
            ));
        }
        if is_workload && host_path_line > 0 {
            findings.push(format!(
                "{{\"line\":{},\"cwe\":\"CWE-250\",\"severity\":\"Critical\",\"kind\":\"{}\",\"name\":\"{}\",\"rule\":\"K8S_SENSITIVE_HOSTPATH\",\"detail\":\"Workload mounts sensitive node path ({})\"}}",
                host_path_line, json_esc_k8s(kind), json_esc_k8s(meta_name), json_esc_k8s(host_path_val)
            ));
        }
        if is_workload && ebpf_cap_line > 0 && !has_seccomp {
            findings.push(format!(
                "{{\"line\":{},\"cwe\":\"CWE-250\",\"severity\":\"High\",\"kind\":\"{}\",\"name\":\"{}\",\"rule\":\"K8S_UNCONFINED_EBPF_CAPABILITY\",\"detail\":\"Workload grants CAP_{} without RuntimeDefault/Localhost seccompProfile\"}}",
                ebpf_cap_line, json_esc_k8s(kind), json_esc_k8s(meta_name), json_esc_k8s(ebpf_cap_name)
            ));
        }
    }

    format!("[{}]", findings.join(","))
}
