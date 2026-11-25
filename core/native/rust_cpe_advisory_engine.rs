// SPECTRE Rust NIST CPE 2.3 Product & SemVer Range Advisory Engine

pub struct CpeProductSpec { pub key: &'static str, pub vendor: &'static str, pub slug: &'static str }
pub struct SemverRuleSpec {
    pub product: &'static str, pub min_v: &'static str, pub max_v: &'static str,
    pub cve: &'static str, pub title: &'static str, pub severity: &'static str, pub cvss_x10: u16, pub cwe: &'static str,
}

pub static CPE_PRODUCTS: &[CpeProductSpec] = &[
    CpeProductSpec { key: "activemq", vendor: "apache", slug: "activemq" },
    CpeProductSpec { key: "airbyte", vendor: "airbyte", slug: "airbyte" },
    CpeProductSpec { key: "airflow", vendor: "apache", slug: "airflow" },
    CpeProductSpec { key: "alertmanager", vendor: "prometheus", slug: "alertmanager" },
    CpeProductSpec { key: "anythingllm", vendor: "mintplexlabs", slug: "anythingllm" },
    CpeProductSpec { key: "apache", vendor: "apache", slug: "http_server" },
    CpeProductSpec { key: "apisix", vendor: "apache", slug: "apisix" },
    CpeProductSpec { key: "appwrite", vendor: "appwrite", slug: "appwrite" },
    CpeProductSpec { key: "argo_workflows", vendor: "argoproj", slug: "argo_workflows" },
    CpeProductSpec { key: "argocd", vendor: "argoproj", slug: "argo_cd" },
    CpeProductSpec { key: "artifactory", vendor: "jfrog", slug: "artifactory" },
    CpeProductSpec { key: "asterisk", vendor: "sangoma", slug: "asterisk" },
    CpeProductSpec { key: "authelia", vendor: "authelia", slug: "authelia" },
    CpeProductSpec { key: "authentik", vendor: "goauthentik", slug: "authentik" },
    CpeProductSpec { key: "bamboo", vendor: "atlassian", slug: "bamboo" },
    CpeProductSpec { key: "bentoml", vendor: "bentoml", slug: "bentoml" },
    CpeProductSpec { key: "bind", vendor: "isc", slug: "bind" },
    CpeProductSpec { key: "bird", vendor: "nic", slug: "bird" },
    CpeProductSpec { key: "bitbucket", vendor: "atlassian", slug: "bitbucket" },
    CpeProductSpec { key: "bitrix", vendor: "1c-bitrix", slug: "site_manager" },
    CpeProductSpec { key: "bookstack", vendor: "bookstackapp", slug: "bookstack" },
    CpeProductSpec { key: "boundary", vendor: "hashicorp", slug: "boundary" },
    CpeProductSpec { key: "caddy", vendor: "caddyserver", slug: "caddy" },
    CpeProductSpec { key: "camunda", vendor: "camunda", slug: "camunda_bpm" },
    CpeProductSpec { key: "cas", vendor: "apereo", slug: "central_authentication_service" },
    CpeProductSpec { key: "casdoor", vendor: "casdoor", slug: "casdoor" },
    CpeProductSpec { key: "cassandra", vendor: "apache", slug: "cassandra" },
    CpeProductSpec { key: "ceph", vendor: "ceph", slug: "ceph" },
    CpeProductSpec { key: "check_point_gaia", vendor: "checkpoint", slug: "gaia_os" },
    CpeProductSpec { key: "chromadb", vendor: "trychroma", slug: "chroma" },
    CpeProductSpec { key: "cisco_ios_xe", vendor: "cisco", slug: "ios_xe" },
    CpeProductSpec { key: "citrix_adc", vendor: "citrix", slug: "application_delivery_controller" },
    CpeProductSpec { key: "clickhouse", vendor: "clickhouse", slug: "clickhouse" },
    CpeProductSpec { key: "cockroachdb", vendor: "cockroachlabs", slug: "cockroachdb" },
    CpeProductSpec { key: "coldfusion", vendor: "adobe", slug: "coldfusion" },
    CpeProductSpec { key: "comfyui", vendor: "comfyanonymous", slug: "comfyui" },
    CpeProductSpec { key: "confluence", vendor: "atlassian", slug: "confluence_server" },
    CpeProductSpec { key: "consul", vendor: "hashicorp", slug: "consul" },
    CpeProductSpec { key: "containerd", vendor: "linuxfoundation", slug: "containerd" },
    CpeProductSpec { key: "coredns", vendor: "coredns", slug: "coredns" },
    CpeProductSpec { key: "corosync", vendor: "corosync", slug: "corosync" },
    CpeProductSpec { key: "cortex", vendor: "cortexmetrics", slug: "cortex" },
    CpeProductSpec { key: "couchdb", vendor: "apache", slug: "couchdb" },
    CpeProductSpec { key: "cpanel", vendor: "cpanel", slug: "whm" },
    CpeProductSpec { key: "cri_o", vendor: "kubernetes", slug: "cri-o" },
    CpeProductSpec { key: "crucible", vendor: "atlassian", slug: "fisheye" },
    CpeProductSpec { key: "cubejs", vendor: "cube", slug: "cubejs" },
    CpeProductSpec { key: "dagster", vendor: "elementl", slug: "dagster" },
    CpeProductSpec { key: "datalife_engine", vendor: "dle-news", slug: "datalife_engine" },
    CpeProductSpec { key: "defectdojo", vendor: "owasp", slug: "defectdojo" },
    CpeProductSpec { key: "dex", vendor: "dexidp", slug: "dex" },
    CpeProductSpec { key: "dify", vendor: "langgenius", slug: "dify" },
    CpeProductSpec { key: "directadmin", vendor: "jbmc-software", slug: "directadmin" },
    CpeProductSpec { key: "directus", vendor: "monospace", slug: "directus" },
    CpeProductSpec { key: "discourse", vendor: "discourse", slug: "discourse" },
    CpeProductSpec { key: "django", vendor: "djangoproject", slug: "django" },
    CpeProductSpec { key: "dnsmasq", vendor: "thekelleys", slug: "dnsmasq" },
    CpeProductSpec { key: "doris", vendor: "apache", slug: "doris" },
    CpeProductSpec { key: "dovecot", vendor: "dovecot", slug: "dovecot" },
    CpeProductSpec { key: "druid", vendor: "apache", slug: "druid" },
    CpeProductSpec { key: "drupal", vendor: "drupal", slug: "drupal" },
    CpeProductSpec { key: "elasticsearch", vendor: "elastic", slug: "elasticsearch" },
    CpeProductSpec { key: "emqx", vendor: "emqx", slug: "emqx" },
    CpeProductSpec { key: "envoy", vendor: "envoyproxy", slug: "envoy" },
    CpeProductSpec { key: "etcd", vendor: "etcd-io", slug: "etcd" },
    CpeProductSpec { key: "exim", vendor: "exim", slug: "exim" },
    CpeProductSpec { key: "f5_bigip", vendor: "f5", slug: "big-ip_access_policy_manager" },
    CpeProductSpec { key: "flink", vendor: "apache", slug: "flink" },
    CpeProductSpec { key: "flowise", vendor: "flowiseai", slug: "flowise" },
    CpeProductSpec { key: "fluent_bit", vendor: "treasuredata", slug: "fluent_bit" },
    CpeProductSpec { key: "forgejo", vendor: "forgejo", slug: "forgejo" },
    CpeProductSpec { key: "fortios", vendor: "fortinet", slug: "fortios" },
    CpeProductSpec { key: "freeswitch", vendor: "signalwire", slug: "freeswitch" },
    CpeProductSpec { key: "frrouting", vendor: "frrouting", slug: "frrouting" },
    CpeProductSpec { key: "ghost", vendor: "ghost", slug: "ghost" },
    CpeProductSpec { key: "gitea", vendor: "gitea", slug: "gitea" },
    CpeProductSpec { key: "gitlab", vendor: "gitlab", slug: "gitlab" },
    CpeProductSpec { key: "glassfish", vendor: "eclipse", slug: "glassfish" },
    CpeProductSpec { key: "glusterfs", vendor: "gluster", slug: "glusterfs" },
    CpeProductSpec { key: "gluu", vendor: "gluu", slug: "gluu_server" },
    CpeProductSpec { key: "gocd", vendor: "gocd", slug: "gocd" },
    CpeProductSpec { key: "gogs", vendor: "gogs", slug: "gogs" },
    CpeProductSpec { key: "gradio", vendor: "gradio_project", slug: "gradio" },
    CpeProductSpec { key: "grafana", vendor: "grafana", slug: "grafana" },
    CpeProductSpec { key: "gravitee", vendor: "gravitee", slug: "api_management" },
    CpeProductSpec { key: "graylog", vendor: "graylog", slug: "graylog" },
    CpeProductSpec { key: "guacamole", vendor: "apache", slug: "guacamole" },
    CpeProductSpec { key: "gunicorn", vendor: "gunicorn", slug: "gunicorn" },
    CpeProductSpec { key: "haproxy", vendor: "haproxy", slug: "haproxy" },
    CpeProductSpec { key: "haproxy_dataplane", vendor: "haproxy", slug: "dataplaneapi" },
    CpeProductSpec { key: "harbor", vendor: "linuxfoundation", slug: "harbor" },
    CpeProductSpec { key: "hasura", vendor: "hasura", slug: "graphql_engine" },
    CpeProductSpec { key: "headscale", vendor: "juanfont", slug: "headscale" },
    CpeProductSpec { key: "hugegraph", vendor: "apache", slug: "hugegraph" },
    CpeProductSpec { key: "iis", vendor: "microsoft", slug: "internet_information_services" },
    CpeProductSpec { key: "influxdb", vendor: "influxdata", slug: "influxdb" },
    CpeProductSpec { key: "ivanti_connect_secure", vendor: "ivanti", slug: "connect_secure" },
    CpeProductSpec { key: "jaeger", vendor: "jaegertracing", slug: "jaeger" },
    CpeProductSpec { key: "jenkins", vendor: "jenkins", slug: "jenkins" },
    CpeProductSpec { key: "jetty", vendor: "eclipse", slug: "jetty" },
    CpeProductSpec { key: "jira", vendor: "atlassian", slug: "jira_server" },
    CpeProductSpec { key: "joomla", vendor: "joomla", slug: "joomla" },
    CpeProductSpec { key: "jquery", vendor: "jquery", slug: "jquery" },
    CpeProductSpec { key: "juniper_junos", vendor: "juniper", slug: "junos" },
    CpeProductSpec { key: "jupyterhub", vendor: "jupyter", slug: "jupyterhub" },
    CpeProductSpec { key: "k3s", vendor: "rancher", slug: "k3s" },
    CpeProductSpec { key: "kafka", vendor: "apache", slug: "kafka" },
    CpeProductSpec { key: "kamailio", vendor: "kamailio", slug: "kamailio" },
    CpeProductSpec { key: "keepalived", vendor: "keepalived", slug: "keepalived" },
    CpeProductSpec { key: "keycloak", vendor: "redhat", slug: "keycloak" },
    CpeProductSpec { key: "kibana", vendor: "elastic", slug: "kibana" },
    CpeProductSpec { key: "knot_resolver", vendor: "nic", slug: "knot_resolver" },
    CpeProductSpec { key: "kong", vendor: "konghq", slug: "kong" },
    CpeProductSpec { key: "krakend", vendor: "krakend", slug: "krakend" },
    CpeProductSpec { key: "langflow", vendor: "langflow", slug: "langflow" },
    CpeProductSpec { key: "laravel", vendor: "laravel", slug: "laravel" },
    CpeProductSpec { key: "librechat", vendor: "danny-avila", slug: "librechat" },
    CpeProductSpec { key: "lighttpd", vendor: "lighttpd", slug: "lighttpd" },
    CpeProductSpec { key: "litellm", vendor: "berriai", slug: "litellm" },
    CpeProductSpec { key: "litespeed", vendor: "litespeedtech", slug: "litespeed_web_server" },
    CpeProductSpec { key: "localai", vendor: "mudler", slug: "localai" },
    CpeProductSpec { key: "logstash", vendor: "elastic", slug: "logstash" },
    CpeProductSpec { key: "loki", vendor: "grafana", slug: "loki" },
    CpeProductSpec { key: "longhorn", vendor: "rancher", slug: "longhorn" },
    CpeProductSpec { key: "mariadb", vendor: "mariadb", slug: "mariadb" },
    CpeProductSpec { key: "mastodon", vendor: "joinmastodon", slug: "mastodon" },
    CpeProductSpec { key: "mattermost", vendor: "mattermost", slug: "mattermost_server" },
    CpeProductSpec { key: "mediawiki", vendor: "mediawiki", slug: "mediawiki" },
    CpeProductSpec { key: "meilisearch", vendor: "meilisearch", slug: "meilisearch" },
    CpeProductSpec { key: "memcached", vendor: "memcached", slug: "memcached" },
    CpeProductSpec { key: "metabase", vendor: "metabase", slug: "metabase" },
    CpeProductSpec { key: "milvus", vendor: "milvus", slug: "milvus" },
    CpeProductSpec { key: "minio", vendor: "minio", slug: "minio" },
    CpeProductSpec { key: "mlflow", vendor: "lfprojects", slug: "mlflow" },
    CpeProductSpec { key: "mongodb", vendor: "mongodb", slug: "mongodb" },
    CpeProductSpec { key: "moodle", vendor: "moodle", slug: "moodle" },
    CpeProductSpec { key: "mosquitto", vendor: "eclipse", slug: "mosquitto" },
    CpeProductSpec { key: "mysql", vendor: "oracle", slug: "mysql" },
    CpeProductSpec { key: "n8n", vendor: "n8n", slug: "n8n" },
    CpeProductSpec { key: "nats", vendor: "nats", slug: "nats_server" },
    CpeProductSpec { key: "neo4j", vendor: "neo4j", slug: "neo4j" },
    CpeProductSpec { key: "netdata", vendor: "netdata", slug: "netdata" },
    CpeProductSpec { key: "nextcloud", vendor: "nextcloud", slug: "nextcloud_server" },
    CpeProductSpec { key: "nextjs", vendor: "vercel", slug: "next.js" },
    CpeProductSpec { key: "nexus", vendor: "sonatype", slug: "nexus_repository_manager" },
    CpeProductSpec { key: "nginx", vendor: "f5", slug: "nginx" },
    CpeProductSpec { key: "nginx_unit", vendor: "nginx", slug: "unit" },
    CpeProductSpec { key: "nifi", vendor: "apache", slug: "nifi" },
    CpeProductSpec { key: "nodejs", vendor: "nodejs", slug: "node.js" },
    CpeProductSpec { key: "nomad", vendor: "hashicorp", slug: "nomad" },
    CpeProductSpec { key: "ofbiz", vendor: "apache", slug: "ofbiz" },
    CpeProductSpec { key: "ojs", vendor: "pkp", slug: "open_journal_systems" },
    CpeProductSpec { key: "ollama", vendor: "ollama", slug: "ollama" },
    CpeProductSpec { key: "open_webui", vendor: "openwebui", slug: "open-webui" },
    CpeProductSpec { key: "openproject", vendor: "openproject", slug: "openproject" },
    CpeProductSpec { key: "openresty", vendor: "openresty", slug: "openresty" },
    CpeProductSpec { key: "opensearch", vendor: "opensearch", slug: "opensearch" },
    CpeProductSpec { key: "opensips", vendor: "opensips", slug: "opensips" },
    CpeProductSpec { key: "openssh", vendor: "openbsd", slug: "openssh" },
    CpeProductSpec { key: "openssl", vendor: "openssl", slug: "openssl" },
    CpeProductSpec { key: "openvpn", vendor: "openvpn", slug: "openvpn" },
    CpeProductSpec { key: "openziti", vendor: "netfoundry", slug: "openziti" },
    CpeProductSpec { key: "opnsense", vendor: "opnsense", slug: "opnsense" },
    CpeProductSpec { key: "ory_hydra", vendor: "ory", slug: "hydra" },
    CpeProductSpec { key: "ory_kratos", vendor: "ory", slug: "kratos" },
    CpeProductSpec { key: "owncloud", vendor: "owncloud", slug: "owncloud" },
    CpeProductSpec { key: "paloalto_panos", vendor: "paloaltonetworks", slug: "pan-os" },
    CpeProductSpec { key: "pfsense", vendor: "netgate", slug: "pfsense" },
    CpeProductSpec { key: "php", vendor: "php", slug: "php" },
    CpeProductSpec { key: "pinot", vendor: "apache", slug: "pinot" },
    CpeProductSpec { key: "plesk", vendor: "plesk", slug: "obsidian" },
    CpeProductSpec { key: "pocketbase", vendor: "pocketbase", slug: "pocketbase" },
    CpeProductSpec { key: "portainer", vendor: "portainer", slug: "portainer" },
    CpeProductSpec { key: "postfix", vendor: "postfix", slug: "postfix" },
    CpeProductSpec { key: "postgresql", vendor: "postgresql", slug: "postgresql" },
    CpeProductSpec { key: "postgrest", vendor: "postgrest", slug: "postgrest" },
    CpeProductSpec { key: "powerdns", vendor: "powerdns", slug: "authoritative" },
    CpeProductSpec { key: "prefect", vendor: "prefect", slug: "prefect" },
    CpeProductSpec { key: "proftpd", vendor: "proftpd", slug: "proftpd" },
    CpeProductSpec { key: "prometheus", vendor: "prometheus", slug: "prometheus" },
    CpeProductSpec { key: "proxmox", vendor: "proxmox", slug: "virtual_environment" },
    CpeProductSpec { key: "pulsar", vendor: "apache", slug: "pulsar" },
    CpeProductSpec { key: "pyroscope", vendor: "grafana", slug: "pyroscope" },
    CpeProductSpec { key: "qdrant", vendor: "qdrant", slug: "qdrant" },
    CpeProductSpec { key: "questdb", vendor: "questdb", slug: "questdb" },
    CpeProductSpec { key: "rabbitmq", vendor: "vmware", slug: "rabbitmq" },
    CpeProductSpec { key: "rancher", vendor: "suse", slug: "rancher" },
    CpeProductSpec { key: "ray", vendor: "anyscale", slug: "ray" },
    CpeProductSpec { key: "redis", vendor: "redis", slug: "redis" },
    CpeProductSpec { key: "redmine", vendor: "redmine", slug: "redmine" },
    CpeProductSpec { key: "redpanda", vendor: "redpanda", slug: "redpanda" },
    CpeProductSpec { key: "rocketchat", vendor: "rocket.chat", slug: "rocket.chat" },
    CpeProductSpec { key: "roundcube", vendor: "roundcube", slug: "webmail" },
    CpeProductSpec { key: "routeros", vendor: "mikrotik", slug: "routeros" },
    CpeProductSpec { key: "rundeck", vendor: "pagerduty", slug: "rundeck" },
    CpeProductSpec { key: "scylladb", vendor: "scylladb", slug: "scylladb" },
    CpeProductSpec { key: "seafile", vendor: "seafile", slug: "seafile" },
    CpeProductSpec { key: "seaweedfs", vendor: "seaweedfs", slug: "seaweedfs" },
    CpeProductSpec { key: "solr", vendor: "apache", slug: "solr" },
    CpeProductSpec { key: "sonarqube", vendor: "sonarsource", slug: "sonarqube" },
    CpeProductSpec { key: "sonicwall_sonicos", vendor: "sonicwall", slug: "sonicos" },
    CpeProductSpec { key: "spark", vendor: "apache", slug: "spark" },
    CpeProductSpec { key: "spinnaker", vendor: "spinnaker", slug: "spinnaker" },
    CpeProductSpec { key: "splunk", vendor: "splunk", slug: "splunk" },
    CpeProductSpec { key: "spring_boot", vendor: "vmware", slug: "spring_boot" },
    CpeProductSpec { key: "spring_framework", vendor: "vmware", slug: "spring_framework" },
    CpeProductSpec { key: "squid", vendor: "squid-cache", slug: "squid" },
    CpeProductSpec { key: "strapi", vendor: "strapi", slug: "strapi" },
    CpeProductSpec { key: "streamlit", vendor: "snowflake", slug: "streamlit" },
    CpeProductSpec { key: "strongswan", vendor: "strongswan", slug: "strongswan" },
    CpeProductSpec { key: "struts", vendor: "apache", slug: "struts" },
    CpeProductSpec { key: "superset", vendor: "apache", slug: "superset" },
    CpeProductSpec { key: "symfony", vendor: "sensiolabs", slug: "symfony" },
    CpeProductSpec { key: "teamcity", vendor: "jetbrains", slug: "teamcity" },
    CpeProductSpec { key: "tekton", vendor: "tekton", slug: "pipelines" },
    CpeProductSpec { key: "teleport", vendor: "goteleport", slug: "teleport" },
    CpeProductSpec { key: "temporal", vendor: "temporal", slug: "server" },
    CpeProductSpec { key: "thanos", vendor: "thanos", slug: "thanos" },
    CpeProductSpec { key: "tidb", vendor: "pingcap", slug: "tidb" },
    CpeProductSpec { key: "tomcat", vendor: "apache", slug: "tomcat" },
    CpeProductSpec { key: "traefik", vendor: "traefik", slug: "traefik" },
    CpeProductSpec { key: "triton_server", vendor: "nvidia", slug: "triton_inference_server" },
    CpeProductSpec { key: "tyk", vendor: "tyk", slug: "tyk_gateway" },
    CpeProductSpec { key: "typesense", vendor: "typesense", slug: "typesense" },
    CpeProductSpec { key: "unbound", vendor: "nlnetlabs", slug: "unbound" },
    CpeProductSpec { key: "undertow", vendor: "redhat", slug: "undertow" },
    CpeProductSpec { key: "uwsgi", vendor: "unbit", slug: "uwsgi" },
    CpeProductSpec { key: "varnish", vendor: "varnish_cache_project", slug: "varnish_cache" },
    CpeProductSpec { key: "vault", vendor: "hashicorp", slug: "vault" },
    CpeProductSpec { key: "vcenter", vendor: "vmware", slug: "vcenter_server" },
    CpeProductSpec { key: "vector_obs", vendor: "timberio", slug: "vector" },
    CpeProductSpec { key: "velero", vendor: "vmware", slug: "velero" },
    CpeProductSpec { key: "vernemq", vendor: "vernemq", slug: "vernemq" },
    CpeProductSpec { key: "victoriametrics", vendor: "victoriametrics", slug: "victoriametrics" },
    CpeProductSpec { key: "vllm", vendor: "vllm_project", slug: "vllm" },
    CpeProductSpec { key: "vmware_esxi", vendor: "vmware", slug: "esxi" },
    CpeProductSpec { key: "vsftpd", vendor: "vsftpd_project", slug: "vsftpd" },
    CpeProductSpec { key: "vyos", vendor: "vyos", slug: "vyos" },
    CpeProductSpec { key: "wazuh", vendor: "wazuh", slug: "wazuh" },
    CpeProductSpec { key: "weaviate", vendor: "weaviate", slug: "weaviate" },
    CpeProductSpec { key: "weblogic", vendor: "oracle", slug: "weblogic_server" },
    CpeProductSpec { key: "webmin", vendor: "webmin", slug: "webmin" },
    CpeProductSpec { key: "wildfly", vendor: "redhat", slug: "wildfly" },
    CpeProductSpec { key: "wordpress", vendor: "wordpress", slug: "wordpress" },
    CpeProductSpec { key: "wso2_apim", vendor: "wso2", slug: "api_manager" },
    CpeProductSpec { key: "wso2_is", vendor: "wso2", slug: "identity_server" },
    CpeProductSpec { key: "zabbix", vendor: "zabbix", slug: "zabbix" },
    CpeProductSpec { key: "zimbra", vendor: "synacor", slug: "zimbra_collaboration_suite" },
    CpeProductSpec { key: "zipkin", vendor: "openzipkin", slug: "zipkin" },
    CpeProductSpec { key: "zookeeper", vendor: "apache", slug: "zookeeper" },
];

pub static SEMVER_ADVISORIES: &[SemverRuleSpec] = &[
    SemverRuleSpec {
        product: "apache", min_v: "2.4.49", max_v: "2.4.51", cve: "CVE-2021-41773 / CVE-2021-42013",
        title: "Apache HTTP Server 2.4.49–2.4.50 Path Normalization Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-22",
    },
    SemverRuleSpec {
        product: "apache", min_v: "2.4.0", max_v: "2.4.59", cve: "CVE-2024-27316",
        title: "Outdated Apache HTTP Server (< 2.4.59) Security Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "apache", min_v: "2.0.0", max_v: "2.3.0", cve: "EOL-APACHE-2.2",
        title: "End-of-Life Apache HTTP Server 2.2.x Unsupported Branch", severity: "High", cvss_x10: 75, cwe: "CWE-1104",
    },
    SemverRuleSpec {
        product: "nginx", min_v: "0.6.18", max_v: "1.20.1", cve: "CVE-2021-23017",
        title: "Outdated nginx (< 1.20.1) DNS Resolver Memory Advisory", severity: "High", cvss_x10: 77, cwe: "CWE-193",
    },
    SemverRuleSpec {
        product: "nginx", min_v: "1.20.1", max_v: "1.25.3", cve: "CVE-2023-44487",
        title: "nginx (< 1.25.3) HTTP/2 Stream Reset Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "openssh", min_v: "8.5", max_v: "9.8", cve: "CVE-2024-6387",
        title: "OpenSSH (8.5–9.7p1) Signal Handler Race Condition Advisory (regreSSHion)", severity: "High", cvss_x10: 81, cwe: "CWE-362",
    },
    SemverRuleSpec {
        product: "openssh", min_v: "1.0", max_v: "8.5", cve: "CVE-2020-14145 / CVE-2021-41617",
        title: "Legacy OpenSSH (< 8.5) Cryptographic & Privilege Escalation Advisory", severity: "Medium", cvss_x10: 64, cwe: "CWE-203",
    },
    SemverRuleSpec {
        product: "php", min_v: "8.1.0", max_v: "8.1.29", cve: "CVE-2024-4577",
        title: "Outdated PHP 8.1 (< 8.1.29) Runtime Security Advisory", severity: "High", cvss_x10: 81, cwe: "CWE-1104",
    },
    SemverRuleSpec {
        product: "php", min_v: "8.2.0", max_v: "8.2.20", cve: "CVE-2024-4577",
        title: "Outdated PHP 8.2 (< 8.2.20) Runtime Security Advisory", severity: "High", cvss_x10: 81, cwe: "CWE-1104",
    },
    SemverRuleSpec {
        product: "php", min_v: "8.3.0", max_v: "8.3.8", cve: "CVE-2024-4577",
        title: "Outdated PHP 8.3 (< 8.3.8) Runtime Security Advisory", severity: "High", cvss_x10: 81, cwe: "CWE-1104",
    },
    SemverRuleSpec {
        product: "php", min_v: "5.0.0", max_v: "8.1.0", cve: "EOL-PHP-LEGACY",
        title: "End-of-Life PHP Runtime (5.x / 7.x / 8.0 Unsupported Branch)", severity: "High", cvss_x10: 75, cwe: "CWE-1104",
    },
    SemverRuleSpec {
        product: "openssl", min_v: "1.0.0", max_v: "1.1.1", cve: "EOL-OPENSSL-1.0",
        title: "End-of-Life OpenSSL 1.0.x Cryptographic Library", severity: "High", cvss_x10: 74, cwe: "CWE-1104",
    },
    SemverRuleSpec {
        product: "openssl", min_v: "1.1.1", max_v: "1.1.1l", cve: "CVE-2021-3711",
        title: "OpenSSL 1.1.1 (< 1.1.1l) SM2 Decryption Buffer Overflow Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-120",
    },
    SemverRuleSpec {
        product: "openssl", min_v: "1.1.1", max_v: "1.1.2", cve: "EOL-OPENSSL-1.1.1",
        title: "End-of-Life OpenSSL 1.1.1 Cryptographic Library Branch", severity: "Medium", cvss_x10: 59, cwe: "CWE-1104",
    },
    SemverRuleSpec {
        product: "openssl", min_v: "3.0.0", max_v: "3.0.7", cve: "CVE-2022-3602 / CVE-2022-3786",
        title: "OpenSSL 3.0.0–3.0.6 X.509 Buffer Overflow Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-120",
    },
    SemverRuleSpec {
        product: "redis", min_v: "2.0.0", max_v: "6.2.7", cve: "CVE-2022-0543",
        title: "Outdated Redis Server (< 6.2.7) Security Advisory", severity: "High", cvss_x10: 81, cwe: "CWE-1104",
    },
    SemverRuleSpec {
        product: "exim", min_v: "4.0.0", max_v: "4.96.2", cve: "CVE-2023-42115",
        title: "Outdated Exim MTA (< 4.96.2) Memory Safety Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-787",
    },
    SemverRuleSpec {
        product: "iis", min_v: "6.0", max_v: "8.6", cve: "EOL-IIS-LEGACY",
        title: "Legacy Microsoft-IIS (6.0–8.5) End-of-Support Server Branch", severity: "Medium", cvss_x10: 65, cwe: "CWE-1104",
    },
    SemverRuleSpec {
        product: "postgresql", min_v: "9.0", max_v: "12.18", cve: "CVE-2024-0985",
        title: "Outdated PostgreSQL (< 12.18 / Legacy Branch) Security Advisory", severity: "High", cvss_x10: 80, cwe: "CWE-269",
    },
    SemverRuleSpec {
        product: "postgresql", min_v: "13.0", max_v: "13.14", cve: "CVE-2024-0985",
        title: "Outdated PostgreSQL 13 (< 13.14) Security Advisory", severity: "High", cvss_x10: 80, cwe: "CWE-269",
    },
    SemverRuleSpec {
        product: "postgresql", min_v: "14.0", max_v: "14.11", cve: "CVE-2024-0985",
        title: "Outdated PostgreSQL 14 (< 14.11) Security Advisory", severity: "High", cvss_x10: 80, cwe: "CWE-269",
    },
    SemverRuleSpec {
        product: "postgresql", min_v: "15.0", max_v: "15.6", cve: "CVE-2024-0985",
        title: "Outdated PostgreSQL 15 (< 15.6) Security Advisory", severity: "High", cvss_x10: 80, cwe: "CWE-269",
    },
    SemverRuleSpec {
        product: "postgresql", min_v: "16.0", max_v: "16.2", cve: "CVE-2024-0985",
        title: "Outdated PostgreSQL 16 (< 16.2) Security Advisory", severity: "High", cvss_x10: 80, cwe: "CWE-269",
    },
    SemverRuleSpec {
        product: "mysql", min_v: "5.0.0", max_v: "5.8.0", cve: "EOL-MYSQL-5.X",
        title: "End-of-Life MySQL 5.x Unsupported Database Branch", severity: "High", cvss_x10: 75, cwe: "CWE-1104",
    },
    SemverRuleSpec {
        product: "mysql", min_v: "8.0.0", max_v: "8.0.36", cve: "CVE-2024-20960",
        title: "Outdated MySQL 8.0 (< 8.0.36) Critical Patch Update Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "mariadb", min_v: "10.0.0", max_v: "10.5.24", cve: "CVE-2023-5157",
        title: "Outdated MariaDB (< 10.5.24 / Legacy 10.x) Security Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "mariadb", min_v: "10.6.0", max_v: "10.6.17", cve: "CVE-2023-5157",
        title: "Outdated MariaDB 10.6 (< 10.6.17) Security Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "postfix", min_v: "2.0.0", max_v: "3.5.24", cve: "CVE-2023-51764",
        title: "Outdated Postfix MTA (< 3.5.24) SMTP Smuggling Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-444",
    },
    SemverRuleSpec {
        product: "postfix", min_v: "3.6.0", max_v: "3.6.13", cve: "CVE-2023-51764",
        title: "Outdated Postfix 3.6 (< 3.6.13) SMTP Smuggling Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-444",
    },
    SemverRuleSpec {
        product: "postfix", min_v: "3.7.0", max_v: "3.7.9", cve: "CVE-2023-51764",
        title: "Outdated Postfix 3.7 (< 3.7.9) SMTP Smuggling Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-444",
    },
    SemverRuleSpec {
        product: "postfix", min_v: "3.8.0", max_v: "3.8.4", cve: "CVE-2023-51764",
        title: "Outdated Postfix 3.8 (< 3.8.4) SMTP Smuggling Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-444",
    },
    SemverRuleSpec {
        product: "spring_boot", min_v: "2.0.0", max_v: "2.6.6", cve: "CVE-2022-22965",
        title: "Spring Boot (< 2.6.6) Data Binding Security Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-94",
    },
    SemverRuleSpec {
        product: "spring_boot", min_v: "2.6.6", max_v: "2.7.18", cve: "CVE-2023-34055",
        title: "Outdated Spring Boot 2.x (< 2.7.18) End-of-OSS-Support Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-1104",
    },
    SemverRuleSpec {
        product: "spring_boot", min_v: "3.0.0", max_v: "3.1.6", cve: "CVE-2023-34055",
        title: "Outdated Spring Boot 3.0/3.1 (< 3.1.6) Security Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "spring_framework", min_v: "5.0.0", max_v: "5.3.18", cve: "CVE-2022-22965",
        title: "Spring Framework (< 5.3.18) Data Binding Security Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-94",
    },
    SemverRuleSpec {
        product: "nextjs", min_v: "10.0.0", max_v: "13.5.7", cve: "CVE-2024-34351",
        title: "Outdated Next.js (< 13.5.7 / Legacy 10–13) Server-Side Handling Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-918",
    },
    SemverRuleSpec {
        product: "nextjs", min_v: "14.0.0", max_v: "14.1.1", cve: "CVE-2024-34351",
        title: "Next.js 14 (< 14.1.1) Server-Side Redirect Handling Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-918",
    },
    SemverRuleSpec {
        product: "tomcat", min_v: "7.0.0", max_v: "9.0.86", cve: "CVE-2024-24549 / CVE-2024-23672",
        title: "Outdated Apache Tomcat (< 9.0.86 / Legacy 7.x–8.5.x) Security Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "tomcat", min_v: "10.0.0", max_v: "10.1.19", cve: "CVE-2024-24549",
        title: "Outdated Apache Tomcat 10 (< 10.1.19) HTTP/2 Header Handling Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "jquery", min_v: "1.0.0", max_v: "3.5.0", cve: "CVE-2020-11022 / CVE-2020-11023",
        title: "Outdated jQuery (< 3.5.0) DOM HTML Prefilter Advisory", severity: "Medium", cvss_x10: 61, cwe: "CWE-79",
    },
    SemverRuleSpec {
        product: "memcached", min_v: "1.0.0", max_v: "1.6.22", cve: "CVE-2023-46852",
        title: "Outdated Memcached (< 1.6.22) Buffer Handling Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-120",
    },
    SemverRuleSpec {
        product: "mongodb", min_v: "2.0.0", max_v: "5.0.0", cve: "EOL-MONGODB-LEGACY",
        title: "End-of-Life MongoDB (2.x–4.x) Unsupported Database Branch", severity: "High", cvss_x10: 75, cwe: "CWE-1104",
    },
    SemverRuleSpec {
        product: "mongodb", min_v: "5.0.0", max_v: "5.0.25", cve: "CVE-2024-1351",
        title: "Outdated MongoDB 5.0 (< 5.0.25) Certificate Validation Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-295",
    },
    SemverRuleSpec {
        product: "mongodb", min_v: "6.0.0", max_v: "6.0.14", cve: "CVE-2024-1351",
        title: "Outdated MongoDB 6.0 (< 6.0.14) Certificate Validation Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-295",
    },
    SemverRuleSpec {
        product: "elasticsearch", min_v: "1.0.0", max_v: "7.17.18", cve: "CVE-2024-23446",
        title: "Outdated Elasticsearch (< 7.17.18) Security Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "elasticsearch", min_v: "8.0.0", max_v: "8.12.1", cve: "CVE-2024-23446",
        title: "Outdated Elasticsearch 8 (< 8.12.1) Security Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "proftpd", min_v: "1.0.0", max_v: "1.3.8b", cve: "CVE-2023-48795",
        title: "Outdated ProFTPD (< 1.3.8b) Prefix Truncation Advisory", severity: "Medium", cvss_x10: 59, cwe: "CWE-354",
    },
    SemverRuleSpec {
        product: "vsftpd", min_v: "1.0.0", max_v: "3.0.4", cve: "CVE-2021-3618",
        title: "Outdated vsFTPd (< 3.0.4) ALPACA TLS Enforcement Advisory", severity: "Medium", cvss_x10: 53, cwe: "CWE-295",
    },
    SemverRuleSpec {
        product: "dovecot", min_v: "1.0.0", max_v: "2.3.21", cve: "CVE-2022-30550",
        title: "Outdated Dovecot (< 2.3.21) Privilege Separation Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-269",
    },
    SemverRuleSpec {
        product: "vsftpd", min_v: "2.3.4", max_v: "2.3.5", cve: "CVE-2011-2523",
        title: "Legacy vsFTPd 2.3.4 Compromised Release Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-506",
    },
    SemverRuleSpec {
        product: "mongodb", min_v: "7.0.0", max_v: "7.0.6", cve: "CVE-2024-1351",
        title: "Outdated MongoDB 7.0 (< 7.0.6) Certificate Validation Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-295",
    },
    SemverRuleSpec {
        product: "jetty", min_v: "7.0.0", max_v: "9.4.54", cve: "CVE-2024-22201",
        title: "Outdated Eclipse Jetty (< 9.4.54 / Legacy 7–9) HTTP/2 Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "jetty", min_v: "10.0.0", max_v: "10.0.20", cve: "CVE-2024-22201",
        title: "Outdated Eclipse Jetty 10 (< 10.0.20) HTTP/2 Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "jetty", min_v: "11.0.0", max_v: "11.0.20", cve: "CVE-2024-22201",
        title: "Outdated Eclipse Jetty 11 (< 11.0.20) HTTP/2 Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "nodejs", min_v: "8.0.0", max_v: "18.0.0", cve: "EOL-NODEJS-LEGACY",
        title: "End-of-Life Node.js (< 18.0.0) Unsupported Runtime Branch", severity: "High", cvss_x10: 75, cwe: "CWE-1104",
    },
    SemverRuleSpec {
        product: "nodejs", min_v: "18.0.0", max_v: "18.20.1", cve: "CVE-2024-27983",
        title: "Outdated Node.js 18 (< 18.20.1) HTTP/2 Frame Handling Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "nodejs", min_v: "20.0.0", max_v: "20.12.1", cve: "CVE-2024-27983",
        title: "Outdated Node.js 20 (< 20.12.1) HTTP/2 Frame Handling Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "wordpress", min_v: "3.0.0", max_v: "6.4.3", cve: "CVE-2024-31210",
        title: "Outdated WordPress Core (< 6.4.3) Security Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-1104",
    },
    SemverRuleSpec {
        product: "drupal", min_v: "6.0.0", max_v: "10.0.0", cve: "EOL-DRUPAL-LEGACY",
        title: "End-of-Life Drupal (6.x–9.x) Unsupported CMS Branch", severity: "High", cvss_x10: 75, cwe: "CWE-1104",
    },
    SemverRuleSpec {
        product: "drupal", min_v: "10.0.0", max_v: "10.2.2", cve: "CVE-2024-22650",
        title: "Outdated Drupal 10 (< 10.2.2) Security Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "joomla", min_v: "1.5.0", max_v: "4.2.8", cve: "CVE-2023-23752",
        title: "Joomla (< 4.2.8) Unauthenticated REST API Information Disclosure", severity: "High", cvss_x10: 75, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "moodle", min_v: "3.0.0", max_v: "4.1.12", cve: "CVE-2024-43425",
        title: "Outdated Moodle LMS (< 4.1.12 LTS) Security Advisory", severity: "High", cvss_x10: 81, cwe: "CWE-94",
    },
    SemverRuleSpec {
        product: "bitrix", min_v: "14.0.0", max_v: "23.300.100", cve: "CVE-2023-1718",
        title: "Outdated 1C-Bitrix Site Manager (< 23.300.100) Security Advisory", severity: "Critical", cvss_x10: 91, cwe: "CWE-287",
    },
    SemverRuleSpec {
        product: "datalife_engine", min_v: "9.0.0", max_v: "16.1.0", cve: "CVE-2023-34843",
        title: "Outdated DataLife Engine (< 16.1) CMS Security Advisory", severity: "High", cvss_x10: 78, cwe: "CWE-89",
    },
    SemverRuleSpec {
        product: "ojs", min_v: "2.4.0", max_v: "3.3.0", cve: "CVE-2022-39059",
        title: "Outdated Open Journal Systems (< 3.3.0) Security Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-22",
    },
    SemverRuleSpec {
        product: "grafana", min_v: "8.0.0", max_v: "8.3.1", cve: "CVE-2021-43798",
        title: "Grafana (8.0.0–8.3.0) Plugin Asset Path Traversal Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-22",
    },
    SemverRuleSpec {
        product: "grafana", min_v: "8.3.1", max_v: "10.4.2", cve: "CVE-2024-9264",
        title: "Outdated Grafana (< 10.4.2) Expression & Auth Advisory", severity: "High", cvss_x10: 81, cwe: "CWE-94",
    },
    SemverRuleSpec {
        product: "zabbix", min_v: "4.0.0", max_v: "6.0.31", cve: "CVE-2024-22120",
        title: "Outdated Zabbix (< 6.0.31 LTS) Server/Frontend Advisory", severity: "Critical", cvss_x10: 91, cwe: "CWE-89",
    },
    SemverRuleSpec {
        product: "gitlab", min_v: "11.0.0", max_v: "16.7.2", cve: "CVE-2023-7028",
        title: "GitLab (< 16.7.2) Password Reset Account Takeover Advisory", severity: "Critical", cvss_x10: 100, cwe: "CWE-640",
    },
    SemverRuleSpec {
        product: "jenkins", min_v: "2.0.0", max_v: "2.442.0", cve: "CVE-2024-23897",
        title: "Jenkins (< 2.442) CLI Argument File Read Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-22",
    },
    SemverRuleSpec {
        product: "keycloak", min_v: "15.0.0", max_v: "24.0.3", cve: "CVE-2024-3656",
        title: "Outdated Keycloak (< 24.0.3) OIDC/Redirect Validation Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-601",
    },
    SemverRuleSpec {
        product: "harbor", min_v: "2.0.0", max_v: "2.10.2", cve: "CVE-2024-22278",
        title: "Outdated Harbor Registry (< 2.10.2) Access Control Advisory", severity: "High", cvss_x10: 81, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "nexus", min_v: "3.0.0", max_v: "3.68.1", cve: "CVE-2024-4956",
        title: "Sonatype Nexus Repository 3 (< 3.68.1) Path Traversal Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-22",
    },
    SemverRuleSpec {
        product: "rabbitmq", min_v: "3.8.0", max_v: "3.12.6", cve: "CVE-2023-46118",
        title: "Outdated RabbitMQ (< 3.12.6) Management API Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "haproxy", min_v: "2.0.0", max_v: "2.8.2", cve: "CVE-2023-40225",
        title: "HAProxy (< 2.8.2) HTTP Request Parsing Advisory", severity: "High", cvss_x10: 82, cwe: "CWE-444",
    },
    SemverRuleSpec {
        product: "traefik", min_v: "2.0.0", max_v: "2.11.2", cve: "CVE-2024-28869",
        title: "Traefik Proxy (< 2.11.2) HTTP/2 Resource Handling Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "envoy", min_v: "1.18.0", max_v: "1.29.3", cve: "CVE-2024-30255",
        title: "Envoy Proxy (< 1.29.3) HTTP/2 CONTINUATION Flood Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "laravel", min_v: "6.0.0", max_v: "10.0.0", cve: "EOL-LARAVEL-LEGACY",
        title: "End-of-Life Laravel Framework (< 10.x) Unsupported Release", severity: "Medium", cvss_x10: 59, cwe: "CWE-1104",
    },
    SemverRuleSpec {
        product: "django", min_v: "1.0.0", max_v: "4.2.15", cve: "CVE-2024-42005",
        title: "Outdated Django (< 4.2.15 LTS) QuerySet Advisory", severity: "Critical", cvss_x10: 91, cwe: "CWE-89",
    },
    SemverRuleSpec {
        product: "symfony", min_v: "2.0.0", max_v: "6.4.4", cve: "CVE-2024-25119",
        title: "Outdated Symfony (< 6.4.4 LTS) Security Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-200",
    },
    SemverRuleSpec {
        product: "struts", min_v: "2.0.0", max_v: "6.3.1", cve: "CVE-2023-50164",
        title: "Apache Struts (< 6.3.0.2) File Upload Path Traversal Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-22",
    },
    SemverRuleSpec {
        product: "confluence", min_v: "6.0.0", max_v: "8.5.4", cve: "CVE-2023-22527",
        title: "Atlassian Confluence (< 8.5.4) Template Advisory", severity: "Critical", cvss_x10: 100, cwe: "CWE-94",
    },
    SemverRuleSpec {
        product: "jira", min_v: "7.0.0", max_v: "9.12.2", cve: "CVE-2024-1597",
        title: "Outdated Atlassian Jira (< 9.12.2 LTS) Security Advisory", severity: "High", cvss_x10: 78, cwe: "CWE-1104",
    },
    SemverRuleSpec {
        product: "sonarqube", min_v: "8.0.0", max_v: "9.9.5", cve: "CVE-2024-43208",
        title: "Outdated SonarQube (< 9.9.5 LTA) Security Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-200",
    },
    SemverRuleSpec {
        product: "argocd", min_v: "2.0.0", max_v: "2.10.10", cve: "CVE-2024-31989",
        title: "Argo CD (< 2.10.10) Redis Cache Advisory", severity: "Critical", cvss_x10: 91, cwe: "CWE-287",
    },
    SemverRuleSpec {
        product: "fortios", min_v: "6.0.0", max_v: "7.4.3", cve: "CVE-2024-21762",
        title: "Fortinet FortiOS (< 7.4.3) SSL-VPN Out-of-Bounds Write Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-787",
    },
    SemverRuleSpec {
        product: "routeros", min_v: "6.0.0", max_v: "7.12.1", cve: "CVE-2023-30799",
        title: "MikroTik RouterOS (< 7.12.1) Management Interface Advisory", severity: "High", cvss_x10: 82, cwe: "CWE-1104",
    },
    SemverRuleSpec {
        product: "citrix_adc", min_v: "12.0.0", max_v: "14.1.12", cve: "CVE-2023-4966",
        title: "Citrix NetScaler ADC (< 14.1) Session Memory Disclosure Advisory", severity: "Critical", cvss_x10: 94, cwe: "CWE-119",
    },
    SemverRuleSpec {
        product: "vmware_esxi", min_v: "6.5.0", max_v: "8.0.2", cve: "CVE-2024-37085",
        title: "VMware ESXi (< 8.0 U2) AD Integration & Hypervisor Advisory", severity: "High", cvss_x10: 88, cwe: "CWE-287",
    },
    SemverRuleSpec {
        product: "litespeed", min_v: "1.0.0", max_v: "1.7.19", cve: "CVE-2024-23952",
        title: "Outdated OpenLiteSpeed / LiteSpeed (< 1.7.19) HTTP Handling Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "squid", min_v: "2.0.0", max_v: "6.6.0", cve: "CVE-2023-46846",
        title: "Outdated Squid Proxy (< 6.6) Chunked Request Parsing Advisory", severity: "High", cvss_x10: 86, cwe: "CWE-444",
    },
    SemverRuleSpec {
        product: "varnish", min_v: "4.0.0", max_v: "7.4.3", cve: "CVE-2024-30156",
        title: "Outdated Varnish Cache (< 7.4.3) HTTP/2 Continuation Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "bind", min_v: "9.0.0", max_v: "9.18.28", cve: "CVE-2024-1737",
        title: "ISC BIND 9 (< 9.18.28) DNS Database Resolver Resource Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "zimbra", min_v: "8.0.0", max_v: "10.0.8", cve: "CVE-2024-27443",
        title: "Outdated Zimbra Collaboration Suite (< 10.0.8) Webmail Advisory", severity: "High", cvss_x10: 78, cwe: "CWE-79",
    },
    SemverRuleSpec {
        product: "roundcube", min_v: "1.0.0", max_v: "1.6.8", cve: "CVE-2024-42009",
        title: "Roundcube Webmail (< 1.6.8) Message Sanitization Advisory", severity: "High", cvss_x10: 82, cwe: "CWE-79",
    },
    SemverRuleSpec {
        product: "kibana", min_v: "7.0.0", max_v: "8.15.1", cve: "CVE-2024-37287",
        title: "Elastic Kibana (< 8.15.1) Prototype Configuration Advisory", severity: "Critical", cvss_x10: 91, cwe: "CWE-1321",
    },
    SemverRuleSpec {
        product: "solr", min_v: "5.0.0", max_v: "9.4.1", cve: "CVE-2023-50298",
        title: "Apache Solr (< 9.4.1) ConfigSet Environment Disclosure Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-200",
    },
    SemverRuleSpec {
        product: "couchdb", min_v: "2.0.0", max_v: "3.3.2", cve: "CVE-2023-26268",
        title: "Apache CouchDB (< 3.3.2) Document Design Isolation Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-200",
    },
    SemverRuleSpec {
        product: "owncloud", min_v: "10.0.0", max_v: "10.13.4", cve: "CVE-2023-49103",
        title: "ownCloud (< 10.13.4) GraphAPI Environment Configuration Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-200",
    },
    SemverRuleSpec {
        product: "nextcloud", min_v: "20.0.0", max_v: "28.0.4", cve: "CVE-2024-32658",
        title: "Outdated Nextcloud Server (< 28.0.4) Access Control Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "gitea", min_v: "1.0.0", max_v: "1.21.11", cve: "CVE-2024-6886",
        title: "Outdated Gitea (< 1.21.11) Repository Permission Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-79",
    },
    SemverRuleSpec {
        product: "mattermost", min_v: "7.0.0", max_v: "9.5.6", cve: "CVE-2024-5146",
        title: "Outdated Mattermost Server (< 9.5.6) Channel Authorization Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "rocketchat", min_v: "3.0.0", max_v: "6.6.6", cve: "CVE-2024-22205",
        title: "Outdated Rocket.Chat (< 6.6.6) Collaboration Server Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "mediawiki", min_v: "1.30.0", max_v: "1.41.1", cve: "CVE-2024-34502",
        title: "Outdated MediaWiki (< 1.41.1) SpecialPage Rendering Advisory", severity: "Medium", cvss_x10: 61, cwe: "CWE-79",
    },
    SemverRuleSpec {
        product: "strapi", min_v: "3.0.0", max_v: "4.20.2", cve: "CVE-2024-34065",
        title: "Outdated Strapi Headless CMS (< 4.20.2) Session Handling Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-287",
    },
    SemverRuleSpec {
        product: "directus", min_v: "9.0.0", max_v: "10.10.5", cve: "CVE-2024-32872",
        title: "Outdated Directus (< 10.10.5) Access Token Policy Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-287",
    },
    SemverRuleSpec {
        product: "dnsmasq", min_v: "2.0.0", max_v: "2.90.0", cve: "CVE-2023-50387",
        title: "Outdated Dnsmasq (< 2.90) DNSSEC KeyTrap Resource Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "powerdns", min_v: "4.0.0", max_v: "4.8.6", cve: "CVE-2023-50868",
        title: "Outdated PowerDNS (< 4.8.6) NSEC3 Validation Resource Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "activemq", min_v: "5.0.0", max_v: "5.18.3", cve: "CVE-2023-46604",
        title: "Apache ActiveMQ (< 5.18.3) OpenWire Class Instantiation Advisory", severity: "Critical", cvss_x10: 100, cwe: "CWE-502",
    },
    SemverRuleSpec {
        product: "superset", min_v: "1.0.0", max_v: "2.1.2", cve: "CVE-2023-27524",
        title: "Apache Superset (< 2.1.2) Default SECRET_KEY Session Validation Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-798",
    },
    SemverRuleSpec {
        product: "metabase", min_v: "0.30.0", max_v: "0.46.6", cve: "CVE-2023-38646",
        title: "Metabase BI (< 0.46.6.1) Pre-Auth Setup Token Validation Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-306",
    },
    SemverRuleSpec {
        product: "airflow", min_v: "2.0.0", max_v: "2.8.2", cve: "CVE-2024-27905",
        title: "Outdated Apache Airflow (< 2.8.2) DAG Configuration Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-200",
    },
    SemverRuleSpec {
        product: "apisix", min_v: "2.0.0", max_v: "3.8.0", cve: "CVE-2023-49070",
        title: "Outdated Apache APISIX (< 3.8.0) Gateway Policy Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "ollama", min_v: "0.1.0", max_v: "0.1.34", cve: "CVE-2024-37032",
        title: "Ollama (< 0.1.34) Model Path Validation Advisory", severity: "Critical", cvss_x10: 91, cwe: "CWE-22",
    },
    SemverRuleSpec {
        product: "mlflow", min_v: "1.0.0", max_v: "2.11.3", cve: "CVE-2024-2928",
        title: "MLflow (< 2.11.3) Artifact URI Traversal Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-22",
    },
    SemverRuleSpec {
        product: "qdrant", min_v: "1.0.0", max_v: "1.9.0", cve: "CVE-2024-3829",
        title: "Qdrant Vector DB (< 1.9.0) Snapshot Upload Validation Advisory", severity: "High", cvss_x10: 81, cwe: "CWE-22",
    },
    SemverRuleSpec {
        product: "flink", min_v: "1.11.0", max_v: "1.18.1", cve: "CVE-2023-47891",
        title: "Outdated Apache Flink (< 1.18.1) Cluster REST Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-200",
    },
    SemverRuleSpec {
        product: "spark", min_v: "3.0.0", max_v: "3.5.1", cve: "CVE-2023-32007",
        title: "Apache Spark (< 3.5.1) UI ACL Command Handling Advisory", severity: "High", cvss_x10: 88, cwe: "CWE-78",
    },
    SemverRuleSpec {
        product: "nomad", min_v: "1.0.0", max_v: "1.7.6", cve: "CVE-2024-3251",
        title: "HashiCorp Nomad (< 1.7.6) ACL Policy Validation Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "rancher", min_v: "2.6.0", max_v: "2.8.3", cve: "CVE-2023-32191",
        title: "SUSE Rancher (< 2.8.3) Kubernetes Secret Handling Advisory", severity: "Critical", cvss_x10: 91, cwe: "CWE-200",
    },
    SemverRuleSpec {
        product: "webmin", min_v: "1.900", max_v: "2.105", cve: "CVE-2023-40224",
        title: "Outdated Webmin (< 2.105) Administrative Session Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "paloalto_panos", min_v: "10.2.0", max_v: "11.1.3", cve: "CVE-2024-3400",
        title: "Palo Alto PAN-OS GlobalProtect Gateway Telemetry Advisory", severity: "Critical", cvss_x10: 100, cwe: "CWE-77",
    },
    SemverRuleSpec {
        product: "ivanti_connect_secure", min_v: "9.0.0", max_v: "22.6.2", cve: "CVE-2024-21887",
        title: "Ivanti Connect Secure Gateway Web Component Advisory", severity: "Critical", cvss_x10: 91, cwe: "CWE-78",
    },
    SemverRuleSpec {
        product: "f5_bigip", min_v: "13.1.0", max_v: "17.1.1", cve: "CVE-2023-46747",
        title: "F5 BIG-IP TMUI Configuration Utility Auth Bypass Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-287",
    },
    SemverRuleSpec {
        product: "cisco_ios_xe", min_v: "16.1.0", max_v: "17.9.4", cve: "CVE-2023-20198",
        title: "Cisco IOS XE Web UI Privilege Escalation Advisory", severity: "Critical", cvss_x10: 100, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "juniper_junos", min_v: "20.4.0", max_v: "23.2.1", cve: "CVE-2023-36845",
        title: "Juniper Junos OS J-Web Environment Variable Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-94",
    },
    SemverRuleSpec {
        product: "sonicwall_sonicos", min_v: "7.0.0", max_v: "7.1.2", cve: "CVE-2024-40766",
        title: "SonicWall SonicOS Access Control & SSLVPN Advisory", severity: "Critical", cvss_x10: 93, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "check_point_gaia", min_v: "80.10", max_v: "81.20", cve: "CVE-2024-24919",
        title: "Check Point Security Gateway Information Disclosure Advisory", severity: "High", cvss_x10: 86, cwe: "CWE-200",
    },
    SemverRuleSpec {
        product: "openvpn", min_v: "2.4.0", max_v: "2.6.10", cve: "CVE-2024-27459",
        title: "Outdated OpenVPN (< 2.6.10) Service Handling Advisory", severity: "High", cvss_x10: 78, cwe: "CWE-122",
    },
    SemverRuleSpec {
        product: "strongswan", min_v: "5.0.0", max_v: "5.9.12", cve: "CVE-2023-41913",
        title: "strongSwan (< 5.9.12) IKEv2 EAP Buffer Handling Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-787",
    },
    SemverRuleSpec {
        product: "unbound", min_v: "1.10.0", max_v: "1.19.1", cve: "CVE-2023-50387",
        title: "NLnet Labs Unbound (< 1.19.1) DNSSEC KeyTrap Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "zookeeper", min_v: "3.4.0", max_v: "3.8.3", cve: "CVE-2023-44981",
        title: "Apache ZooKeeper (< 3.8.3) SASL Quorum Authorization Advisory", severity: "Critical", cvss_x10: 91, cwe: "CWE-285",
    },
    SemverRuleSpec {
        product: "druid", min_v: "0.15.0", max_v: "25.0.0", cve: "CVE-2023-25194",
        title: "Apache Druid (< 25.0.0) Kafka Connector Configuration Advisory", severity: "High", cvss_x10: 88, cwe: "CWE-502",
    },
    SemverRuleSpec {
        product: "nifi", min_v: "1.10.0", max_v: "1.22.0", cve: "CVE-2023-34468",
        title: "Apache NiFi (< 1.22.0) DBCP Connection Pool Validation Advisory", severity: "High", cvss_x10: 88, cwe: "CWE-94",
    },
    SemverRuleSpec {
        product: "guacamole", min_v: "1.0.0", max_v: "1.5.2", cve: "CVE-2023-30575",
        title: "Apache Guacamole (< 1.5.2) RDP Protocol Handling Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-416",
    },
    SemverRuleSpec {
        product: "ofbiz", min_v: "17.0.0", max_v: "18.12.15", cve: "CVE-2024-38856",
        title: "Apache OFBiz (< 18.12.15) Controller View Override Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "hugegraph", min_v: "1.0.0", max_v: "1.3.0", cve: "CVE-2024-27348",
        title: "Apache HugeGraph-Server (< 1.3.0) Gremlin Sandbox Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-94",
    },
    SemverRuleSpec {
        product: "teamcity", min_v: "2018.1.0", max_v: "2023.11.4", cve: "CVE-2024-27198",
        title: "JetBrains TeamCity (< 2023.11.4) Web Authentication Bypass Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-288",
    },
    SemverRuleSpec {
        product: "bamboo", min_v: "8.0.0", max_v: "9.6.1", cve: "CVE-2024-1597",
        title: "Atlassian Bamboo (< 9.6.1) Data Center Dependency Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-89",
    },
    SemverRuleSpec {
        product: "bitbucket", min_v: "7.0.0", max_v: "8.3.1", cve: "CVE-2022-36804",
        title: "Atlassian Bitbucket Server (< 8.3.1) Git Archive Advisory", severity: "Critical", cvss_x10: 99, cwe: "CWE-78",
    },
    SemverRuleSpec {
        product: "crucible", min_v: "4.0.0", max_v: "4.8.14", cve: "CVE-2024-21683",
        title: "Atlassian Fisheye / Crucible (< 4.8.14) Template Advisory", severity: "High", cvss_x10: 83, cwe: "CWE-94",
    },
    SemverRuleSpec {
        product: "splunk", min_v: "8.0.0", max_v: "9.2.2", cve: "CVE-2024-36991",
        title: "Splunk Enterprise (< 9.2.2) Windows Modules Path Traversal Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-22",
    },
    SemverRuleSpec {
        product: "wazuh", min_v: "4.0.0", max_v: "4.7.2", cve: "CVE-2024-24497",
        title: "Outdated Wazuh SIEM (< 4.7.2) Cluster API Validation Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "graylog", min_v: "4.0.0", max_v: "5.1.6", cve: "CVE-2023-41044",
        title: "Graylog (< 5.1.6) Support Bundle Information Exposure Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-200",
    },
    SemverRuleSpec {
        product: "victoriametrics", min_v: "1.50.0", max_v: "1.99.0", cve: "CVE-2024-27918",
        title: "Outdated VictoriaMetrics (< 1.99.0) Metrics UI Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-200",
    },
    SemverRuleSpec {
        product: "meilisearch", min_v: "0.20.0", max_v: "1.2.0", cve: "CVE-2023-33968",
        title: "Outdated Meilisearch (< 1.2.0) Master Key Posture Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-287",
    },
    SemverRuleSpec {
        product: "chromadb", min_v: "0.3.0", max_v: "0.4.24", cve: "CVE-2024-29028",
        title: "ChromaDB (< 0.4.24) Vector Store Authentication Posture Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-306",
    },
    SemverRuleSpec {
        product: "ray", min_v: "2.0.0", max_v: "2.8.1", cve: "CVE-2023-48022",
        title: "Anyscale Ray (< 2.8.1) Unauthenticated Jobs Submission API Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-306",
    },
    SemverRuleSpec {
        product: "gradio", min_v: "3.0.0", max_v: "4.19.2", cve: "CVE-2024-1561",
        title: "Gradio (< 4.19.2) Arbitrary File Read via Component API Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-22",
    },
    SemverRuleSpec {
        product: "langflow", min_v: "0.5.0", max_v: "1.0.15", cve: "CVE-2024-3120",
        title: "Outdated Langflow (< 1.0.15) Workflow Validation Advisory", severity: "High", cvss_x10: 78, cwe: "CWE-94",
    },
    SemverRuleSpec {
        product: "cockroachdb", min_v: "21.1.0", max_v: "23.1.9", cve: "CVE-2023-38443",
        title: "Outdated CockroachDB (< 23.1.9) SQL Privilege Evaluation Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "vernemq", min_v: "1.0.0", max_v: "1.12.0", cve: "CVE-2021-34432",
        title: "Outdated VerneMQ (< 1.12.0) MQTT Broker ACL Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "emqx", min_v: "4.0.0", max_v: "5.1.0", cve: "CVE-2023-35848",
        title: "Outdated EMQX (< 5.1.0) MQTT Dashboard API Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-287",
    },
    SemverRuleSpec {
        product: "mosquitto", min_v: "1.6.0", max_v: "2.0.16", cve: "CVE-2023-28366",
        title: "Eclipse Mosquitto (< 2.0.16) QoS Memory Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-401",
    },
    SemverRuleSpec {
        product: "coredns", min_v: "1.5.0", max_v: "1.10.1", cve: "CVE-2023-30464",
        title: "Outdated CoreDNS (< 1.10.1) DNS Cache Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "knot_resolver", min_v: "5.0.0", max_v: "5.7.1", cve: "CVE-2023-50868",
        title: "Outdated Knot Resolver (< 5.7.1) DNSSEC Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "nginx_unit", min_v: "1.10.0", max_v: "1.31.1", cve: "CVE-2023-44487",
        title: "Outdated NGINX Unit (< 1.31.1) HTTP/2 Reset Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "undertow", min_v: "2.0.0", max_v: "2.3.10", cve: "CVE-2023-5685",
        title: "Red Hat Undertow (< 2.3.10) Stream Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "wildfly", min_v: "20.0.0", max_v: "30.0.1", cve: "CVE-2023-5685",
        title: "Outdated WildFly (< 30.0.1) Application Server Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "glassfish", min_v: "5.0.0", max_v: "7.0.9", cve: "CVE-2023-4043",
        title: "Eclipse GlassFish (< 7.0.9) Admin File Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-22",
    },
    SemverRuleSpec {
        product: "weblogic", min_v: "12.2.1", max_v: "14.1.2", cve: "CVE-2023-21839",
        title: "Oracle WebLogic (< 14.1.2) IIOP/T3 JNDI Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-502",
    },
    SemverRuleSpec {
        product: "coldfusion", min_v: "2021.0.0", max_v: "2023.0.7", cve: "CVE-2024-20767",
        title: "Adobe ColdFusion (< 2023.0.7) Access Control Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "ghost", min_v: "5.0.0", max_v: "5.59.1", cve: "CVE-2023-40028",
        title: "Ghost CMS (< 5.59.1) Symlink Import Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-59",
    },
    SemverRuleSpec {
        product: "discourse", min_v: "2.8.0", max_v: "3.2.1", cve: "CVE-2024-27098",
        title: "Outdated Discourse (< 3.2.1) API Input Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "mastodon", min_v: "3.5.0", max_v: "4.2.5", cve: "CVE-2024-23832",
        title: "Mastodon (< 4.2.5) Origin Signature Advisory", severity: "Critical", cvss_x10: 94, cwe: "CWE-347",
    },
    SemverRuleSpec {
        product: "seafile", min_v: "8.0.0", max_v: "10.0.2", cve: "CVE-2023-38500",
        title: "Outdated Seafile (< 10.0.2) Share Link Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "openproject", min_v: "11.0.0", max_v: "13.0.6", cve: "CVE-2023-45136",
        title: "OpenProject (< 13.0.6) Attachment Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-79",
    },
    SemverRuleSpec {
        product: "bookstack", min_v: "21.0.0", max_v: "23.10.4", cve: "CVE-2023-49803",
        title: "BookStack (< 23.10.4) SSRF Filter Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-918",
    },
    SemverRuleSpec {
        product: "pocketbase", min_v: "0.10.0", max_v: "0.18.0", cve: "CVE-2023-41338",
        title: "Outdated PocketBase (< 0.18.0) Filter Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-200",
    },
    SemverRuleSpec {
        product: "appwrite", min_v: "1.0.0", max_v: "1.3.2", cve: "CVE-2023-27159",
        title: "Appwrite (< 1.3.2) Webhook SSRF Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-918",
    },
    SemverRuleSpec {
        product: "typesense", min_v: "0.20.0", max_v: "0.25.2", cve: "CVE-2023-46233",
        title: "Outdated Typesense (< 0.25.2) Search Key Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "milvus", min_v: "2.0.0", max_v: "2.3.3", cve: "CVE-2023-29510",
        title: "Outdated Milvus (< 2.3.3) Proxy Auth Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-306",
    },
    SemverRuleSpec {
        product: "triton_server", min_v: "22.01.0", max_v: "24.04.0", cve: "CVE-2024-0087",
        title: "NVIDIA Triton (< 24.04) Shared Memory Advisory", severity: "High", cvss_x10: 81, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "vllm", min_v: "0.2.0", max_v: "0.6.2", cve: "CVE-2024-9052",
        title: "vLLM (< 0.6.2) Distributed RPC Deserialization Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-502",
    },
    SemverRuleSpec {
        product: "litellm", min_v: "1.10.0", max_v: "1.40.0", cve: "CVE-2024-5225",
        title: "LiteLLM (< 1.40.0) Admin Key Validation Advisory", severity: "High", cvss_x10: 86, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "dify", min_v: "0.3.0", max_v: "0.6.13", cve: "CVE-2024-39848",
        title: "Dify (< 0.6.13) Sandbox SSRF Advisory", severity: "High", cvss_x10: 82, cwe: "CWE-918",
    },
    SemverRuleSpec {
        product: "authelia", min_v: "4.0.0", max_v: "4.38.0", cve: "CVE-2024-27302",
        title: "Outdated Authelia (< 4.38.0) OIDC Consent Validation Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-287",
    },
    SemverRuleSpec {
        product: "authentik", min_v: "2022.1.0", max_v: "2024.2.2", cve: "CVE-2024-21637",
        title: "Outdated Authentik (< 2024.2.2) Session Token Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-287",
    },
    SemverRuleSpec {
        product: "dex", min_v: "2.20.0", max_v: "2.37.0", cve: "CVE-2023-39325",
        title: "Outdated Dex OIDC (< 2.37.0) HTTP/2 Resource Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "cas", min_v: "6.0.0", max_v: "6.6.14", cve: "CVE-2023-25859",
        title: "Apereo CAS (< 6.6.14) SSO Ticket Validation Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-287",
    },
    SemverRuleSpec {
        product: "gluu", min_v: "4.0.0", max_v: "4.5.4", cve: "CVE-2023-44487",
        title: "Outdated Gluu Server (< 4.5.4) IAM Runtime Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "wso2_is", min_v: "5.3.0", max_v: "6.1.0", cve: "CVE-2022-29464",
        title: "WSO2 Identity Server (< 6.1.0) File Upload Path Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-22",
    },
    SemverRuleSpec {
        product: "wso2_apim", min_v: "3.0.0", max_v: "4.2.0", cve: "CVE-2022-29464",
        title: "WSO2 API Manager (< 4.2.0) Endpoint Upload Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-22",
    },
    SemverRuleSpec {
        product: "gravitee", min_v: "3.15.0", max_v: "4.1.2", cve: "CVE-2023-38501",
        title: "Gravitee APIM (< 4.1.2) Expression Language Advisory", severity: "High", cvss_x10: 88, cwe: "CWE-94",
    },
    SemverRuleSpec {
        product: "tyk", min_v: "4.0.0", max_v: "5.2.2", cve: "CVE-2023-44487",
        title: "Outdated Tyk Gateway (< 5.2.2) HTTP/2 Stream Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "krakend", min_v: "2.0.0", max_v: "2.5.0", cve: "CVE-2023-44487",
        title: "Outdated KrakenD (< 2.5.0) API Gateway Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "pfsense", min_v: "2.4.0", max_v: "2.7.1", cve: "CVE-2023-42326",
        title: "Netgate pfSense (< 2.7.1) WebGUI Input Validation Advisory", severity: "High", cvss_x10: 88, cwe: "CWE-78",
    },
    SemverRuleSpec {
        product: "opnsense", min_v: "22.1.0", max_v: "23.7.8", cve: "CVE-2023-48222",
        title: "Outdated OPNsense (< 23.7.8) Firewall UI Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-79",
    },
    SemverRuleSpec {
        product: "vyos", min_v: "1.2.0", max_v: "1.4.0", cve: "CVE-2023-48795",
        title: "Outdated VyOS (< 1.4.0) SSH Transport Advisory", severity: "Medium", cvss_x10: 59, cwe: "CWE-354",
    },
    SemverRuleSpec {
        product: "frrouting", min_v: "7.5.0", max_v: "9.0.2", cve: "CVE-2023-47235",
        title: "FRRouting (< 9.0.2) BGP Attribute Parsing Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-476",
    },
    SemverRuleSpec {
        product: "bird", min_v: "2.0.0", max_v: "2.14.0", cve: "CVE-2023-44487",
        title: "Outdated BIRD Routing Daemon (< 2.14.0) Advisory", severity: "Medium", cvss_x10: 59, cwe: "CWE-400",
    },
    SemverRuleSpec {
        product: "keepalived", min_v: "2.0.0", max_v: "2.2.8", cve: "CVE-2021-44225",
        title: "Outdated Keepalived (< 2.2.8) D-Bus Access Control Advisory", severity: "High", cvss_x10: 78, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "corosync", min_v: "2.4.0", max_v: "3.1.8", cve: "CVE-2021-3879",
        title: "Outdated Corosync (< 3.1.8) Packet Validation Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-120",
    },
    SemverRuleSpec {
        product: "ceph", min_v: "15.0.0", max_v: "18.2.1", cve: "CVE-2023-43040",
        title: "Ceph Storage (< 18.2.1) RGW Bucket Policy Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "glusterfs", min_v: "9.0.0", max_v: "11.1.0", cve: "CVE-2023-26253",
        title: "Outdated GlusterFS (< 11.1.0) Buffer Handling Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-787",
    },
    SemverRuleSpec {
        product: "longhorn", min_v: "1.2.0", max_v: "1.5.4", cve: "CVE-2024-21650",
        title: "Rancher Longhorn (< 1.5.4) UI Proxy Exposure Advisory", severity: "High", cvss_x10: 75, cwe: "CWE-284",
    },
    SemverRuleSpec {
        product: "velero", min_v: "1.8.0", max_v: "1.12.3", cve: "CVE-2024-23331",
        title: "VMware Velero (< 1.12.3) Backup Credential Log Advisory", severity: "Medium", cvss_x10: 65, cwe: "CWE-532",
    },
    SemverRuleSpec {
        product: "k3s", min_v: "1.24.0", max_v: "1.28.6", cve: "CVE-2024-21626",
        title: "Outdated K3s Kubernetes (< 1.28.6) Runtime Advisory", severity: "High", cvss_x10: 86, cwe: "CWE-200",
    },
    SemverRuleSpec {
        product: "containerd", min_v: "1.5.0", max_v: "1.7.13", cve: "CVE-2024-21626",
        title: "Outdated containerd (< 1.7.13) File Descriptor Escape Advisory", severity: "High", cvss_x10: 86, cwe: "CWE-250",
    },
    SemverRuleSpec {
        product: "cri_o", min_v: "1.24.0", max_v: "1.28.4", cve: "CVE-2024-21626",
        title: "Outdated CRI-O (< 1.28.4) Container Runtime Advisory", severity: "High", cvss_x10: 86, cwe: "CWE-250",
    },
    SemverRuleSpec {
        product: "fluent_bit", min_v: "2.0.0", max_v: "3.0.4", cve: "CVE-2024-4323",
        title: "Fluent Bit (< 3.0.4) Embedded HTTP Server Memory Advisory", severity: "Critical", cvss_x10: 98, cwe: "CWE-787",
    },
];

pub fn lookup_cpe_vendor_slug(key: &str) -> Option<(&'static str, &'static str)> {
    let idx = CPE_PRODUCTS.binary_search_by(|e| e.key.cmp(key)).ok()?;
    Some((CPE_PRODUCTS[idx].vendor, CPE_PRODUCTS[idx].slug))
}
