// SPECTRE C++17 v9.0 Static .rodata Shard 1
#include "spectre_nvt_rodata.hpp"
#include <algorithm>
#include <cstring>
namespace {
using spectre_rodata::FaviconSpec;
using spectre_rodata::NativeNvtSpec;
static const FaviconSpec kFaviconTable[] = {
    {-2031827364, "AdGuard Home"},
    {-1950415971, "Joomla CMS"},
    {-1942837165, "Pi-hole Admin"},
    {-1934461592, "Mattermost"},
    {-1847263519, "WildFly Application Server"},
    {-1840324437, "Proxmox VE"},
    {-1839201745, "MinIO Console"},
    {-1762839104, "TrueNAS Scale"},
    {-1748308192, "MikroTik RouterOS WebFig"},
    {-1728394012, "Directus Data Platform"},
    {-1636196006, "Nextcloud"},
    {-1627384910, "Apache Superset"},
    {-1616143106, "ownCloud"},
    {-1582736491, "Veeam Backup Enterprise Manager"},
    {-1581907337, "Keycloak SSO"},
    {-1569788234, "Neo4j Browser"},
    {-1520918473, "Graylog SIEM"},
    {-1492837162, "JFrog Artifactory"},
    {-1492576298, "SUSE Rancher"},
    {-1465728391, "Ivanti Connect Secure"},
    {-1459687123, "Apache CouchDB Fauxton"},
    {-1459632189, "Argo CD"},
    {-1424036600, "Portainer"},
    {-1399433489, "Prometheus"},
    {-1384726190, "JetBrains TeamCity"},
    {-1340928172, "QNAP QTS NAS"},
    {-1293291541, "Plesk Panel"},
    {-1273645189, "Atlassian Bamboo"},
    {-1255329781, "VMware ESXi"},
    {-1248526899, "Adminer DB"},
    {-1239485761, "EMQX MQTT Dashboard"},
    {-1208998316, "Rocket.Chat"},
    {-1198204712, "HashiCorp Vault"},
    {-1193573398, "WordPress"},
    {-1182736450, "Wazuh Dashboard"},
    {-1166125415, "Citrix NetScaler Gateway"},
    {-1162534189, "Atlassian Bitbucket"},
    {-1148190371, "OPNsense Firewall"},
    {-1129384756, "Home Assistant"},
    {-1092837461, "Apache Guacamole"},
    {-1073812648, "Drupal CMS"},
    {-1067945891, "DirectAdmin"},
    {-1038836350, "Sonatype Nexus"},
    {-981726354, "Ghost CMS"},
    {-928374615, "Apache Airflow"},
    {-927163548, "Authentik IdP"},
    {-918273640, "Appwrite Console"},
    {-913084217, "Splunk Enterprise"},
    {-890624739, "VMware vCenter"},
    {-832910482, "HashiCorp Nomad"},
    {-827364519, "Open WebUI"},
    {-827163540, "Anyscale Ray Dashboard"},
    {-819273645, "NetBox DCIM"},
    {-817263549, "Seafile Cloud"},
    {-768816037, "Ubiquiti UniFi Controller"},
    {-759102834, "HashiCorp Consul"},
    {-726153489, "Meilisearch"},
    {-718293645, "KrakenD Gateway"},
    {-716253498, "Dify LLM Ops"},
    {-672819304, "Jupyter Server"},
    {-637281904, "Langflow Studio"},
    {-631507152, "Palo Alto GlobalProtect"},
    {-629032489, "Eclipse Jetty"},
    {-617283912, "Kong Manager"},
    {-615243890, "BookStack Wiki"},
    {-528374619, "n8n Workflow Automation"},
    {-519283746, "Traefik Dashboard"},
    {-519283104, "Apache APISIX Dashboard"},
    {-518273640, "Authelia SSO"},
    {-514263780, "Qdrant Dashboard"},
    {-482716390, "Oracle WebLogic Console"},
    {-476231906, "phpMyAdmin"},
    {-438482901, "Moodle LMS"},
    {-419283746, "Uptime Kuma"},
    {-418273910, "Gravitee APIM"},
    {-418273645, "MLflow Tracking UI"},
    {-415263789, "Milvus Attu"},
    {-381927460, "PocketBase Admin"},
    {-335242539, "F5 BIG-IP TMUI"},
    {-319283741, "Ollama API"},
    {-317263548, "WSO2 Carbon Management"},
    {-305179312, "Grafana"},
    {-305179311, "Atlassian Confluence"},
    {-299287097, "Cisco IOS XE WebUI"},
    {-297069493, "Apache Tomcat"},
    {-291837465, "MediaWiki"},
    {-267431135, "Elastic Kibana"},
    {-218374659, "Gradio AI App"},
    {81586312, "Jenkins"},
    {81586313, "Jenkins BlueOcean"},
    {116323821, "Spring Boot"},
    {149371702, "Synology DiskStation DSM"},
    {617283940, "Redmine Tracker"},
    {631108382, "SonicWall SSL-VPN"},
    {657337228, "Harbor Registry"},
    {708578229, "Bitrix CMS"},
    {792837461, "Check Point Gaia Portal"},
    {892542951, "Zabbix Monitoring"},
    {945408572, "FortiGate SSL VPN"},
    {981867722, "Atlassian Jira"},
    {1061819723, "RabbitMQ Management"},
    {1278323681, "GitLab"},
    {1280907314, "Webmin"},
    {1349281726, "Strapi Headless CMS"},
    {1405460984, "Netgate pfSense"},
    {1485257654, "Roundcube Webmail"},
    {1485257655, "SonarQube"},
    {1624375939, "Zimbra Web Client"},
    {1768726119, "Microsoft OWA (Exchange)"},
    {1937281920, "Metabase BI"},
    {1993518473, "cPanel WHM"},
    {2142622726, "Gitea"},
};
static const NativeNvtSpec kNativeNvtPart1[] = {
    {
        "NVT-INFRA-001",
        "Exposed Apache httpd Server-Status Telemetry",
        "Infrastructure Telemetry Exposure", "Medium", 58, "CWE-200",
        "/server-status?auto", 200,
        "total accesses:", "score",
        ""
    },
    {
        "NVT-INFRA-002",
        "Exposed Nginx Stub-Status Metrics",
        "Infrastructure Telemetry Exposure", "Low", 37, "CWE-200",
        "/nginx_status", 200,
        "active connections:", "server accepts handled requests",
        ""
    },
    {
        "NVT-INFRA-003",
        "Exposed PHP-FPM Real-Time Pool Status",
        "Infrastructure Telemetry Exposure", "Medium", 53, "CWE-200",
        "/status?full&json", 200,
        "\"pool\"", "\"accepted conn\"",
        ""
    },
    {
        "NVT-INFRA-004",
        "Exposed PHP Runtime Configuration (phpinfo)",
        "Sensitive Environment Exposure", "High", 75, "CWE-200",
        "/phpinfo.php", 200,
        "php version", "system",
        ""
    },
    {
        "NVT-DEVOPS-005",
        "Unauthenticated Traefik Reverse-Proxy Dashboard API",
        "Reverse-Proxy Control Exposure", "High", 75, "CWE-306",
        "/api/rawdata", 200,
        "\"routers\"", "\"services\"",
        ""
    },
    {
        "NVT-DEVOPS-006",
        "Unauthenticated Kibana Status & Saved Objects API",
        "Monitoring / SIEM Exposure", "High", 75, "CWE-306",
        "/api/status", 200,
        "\"status\"", "\"overall\"",
        ""
    },
    {
        "NVT-DEVOPS-007",
        "Exposed Portainer System Status & Uninitialized Setup",
        "Container Management Exposure", "High", 82, "CWE-306",
        "/api/system/status", 200,
        "\"version\"", "\"instanceid\"",
        ""
    },
    {
        "NVT-DEVOPS-008",
        "Unauthenticated Harbor Registry Public Projects Catalog",
        "Container Registry Exposure", "Medium", 65, "CWE-200",
        "/api/v2.0/projects?public=true", 200,
        "\"project_id\"", "\"name\"",
        ""
    },
    {
        "NVT-DB-009",
        "Unauthenticated Apache Solr Admin Cores API",
        "Database / Search Exposure", "Critical", 91, "CWE-306",
        "/solr/admin/cores?wt=json", 200,
        "\"responseheader\"", "\"status\"",
        ""
    },
    {
        "NVT-DB-010",
        "Unauthenticated Apache CouchDB All-Databases Endpoint",
        "Database / Cache Exposure", "Critical", 91, "CWE-306",
        "/_all_dbs", 200,
        "\"_users\"", "",
        ""
    },
    {
        "NVT-APP-011",
        "Exposed Laravel Horizon Queue Dashboard API",
        "Debug / Queue Control Exposure", "High", 81, "CWE-306",
        "/horizon/api/stats", 200,
        "\"jobsperminute\"", "\"status\"",
        ""
    },
    {
        "NVT-APP-012",
        "Exposed Symfony Web Profiler Debug Toolbar",
        "Debug Mode Exposure", "High", 78, "CWE-489",
        "/_profiler/empty/search/results?limit=5", 200,
        "symfony profiler", "token",
        ""
    },
    {
        "NVT-APP-013",
        "Exposed HAProxy Load-Balancer Statistics Page",
        "Infrastructure Telemetry Exposure", "Medium", 58, "CWE-200",
        "/haproxy?stats", 200,
        "statistics report for pid", "haproxy",
        ""
    },
    {
        "NVT-APP-014",
        "Exposed Prometheus Server Targets & Service Discovery",
        "Monitoring / SIEM Exposure", "High", 75, "CWE-200",
        "/api/v1/targets", 200,
        "\"activetargets\"", "\"scrapeurl\"",
        ""
    },
    {
        "NVT-SEC-015",
        "Exposed HashiCorp Vault Seal & Cluster Status API",
        "Secrets Management Exposure", "Medium", 53, "CWE-200",
        "/v1/sys/seal-status", 200,
        "\"sealed\"", "\"cluster_name\"",
        ""
    },
    {
        "NVT-DEVOPS-016",
        "Unauthenticated SonarQube System Info & Plugins API",
        "DevSecOps Platform Exposure", "High", 75, "CWE-200",
        "/api/system/info", 200,
        "\"system\"", "\"plugins\"",
        ""
    },
    {
        "NVT-DB-017",
        "Unauthenticated ClickHouse HTTP SQL Interface",
        "Database / Analytics Exposure", "Critical", 94, "CWE-306",
        "/?query=SELECT%20version()", 200,
        "2", "",
        ""
    },
    {
        "NVT-DB-018",
        "Exposed InfluxDB Debug Runtime Variables (/debug/vars)",
        "Database Telemetry Exposure", "Medium", 58, "CWE-200",
        "/debug/vars", 200,
        "\"cmdline\"", "\"memstats\"",
        ""
    },
    {
        "NVT-DEVOPS-019",
        "Exposed ArgoCD Server Settings & OIDC Configuration",
        "GitOps Control-Plane Exposure", "Medium", 53, "CWE-200",
        "/api/v1/settings", 200,
        "\"clusterlabelledby\"", "\"appLabelKey\"",
        ""
    },
    {
        "NVT-DEVOPS-020",
        "Publicly Accessible GitLab Internal/Public Repositories Feed",
        "Source Code Repository Exposure", "Medium", 65, "CWE-200",
        "/api/v4/projects?visibility=public&per_page=5", 200,
        "\"path_with_namespace\"", "\"http_url_to_repo\"",
        ""
    },
    {
        "NVT-APP-021",
        "Exposed PHP Composer Dependency Manifest (composer.json)",
        "Dependency & Version Disclosure", "Low", 37, "CWE-200",
        "/composer.json", 200,
        "\"require\"", "",
        ""
    },
    {
        "NVT-APP-022",
        "Exposed Spring Boot Actuator Route Mappings (/actuator/mappings)",
        "Internal API Topology Exposure", "High", 75, "CWE-200",
        "/actuator/mappings", 200,
        "\"contexts\"", "\"dispatcherServlets\"",
        ""
    },
    {
        "NVT-APP-023",
        "Exposed Directus Headless CMS Server Ping & Info",
        "CMS Metadata Exposure", "Low", 37, "CWE-200",
        "/server/info", 200,
        "\"project\"", "",
        ""
    },
    {
        "NVT-APP-024",
        "Exposed Nextcloud / ownCloud Instance Version Status",
        "Software Version Disclosure", "Low", 37, "CWE-200",
        "/status.php", 200,
        "\"installed\"", "\"versionstring\"",
        ""
    },
    {
        "NVT-APP-025",
        "Publicly Accessible Gitea / Gogs Source Repositories API",
        "Source Code Repository Exposure", "Medium", 65, "CWE-200",
        "/api/v1/repos/search?limit=5", 200,
        "\"ok\"", "\"data\"",
        ""
    },
    {
        "NVT-APP-026",
        "Exposed Mattermost Server Configuration & Ping Telemetry",
        "Collaboration Platform Exposure", "Low", 37, "CWE-200",
        "/api/v4/system/ping", 200,
        "\"status\"", "\"active_backend\"",
        ""
    },
    {
        "NVT-APP-027",
        "Exposed Rocket.Chat Server Version Build Info",
        "Software Version Disclosure", "Low", 37, "CWE-200",
        "/api/info", 200,
        "\"version\"", "\"success\"",
        ""
    },
    {
        "NVT-APP-028",
        "Publicly Accessible Redmine Projects & Issue Tracker API",
        "Project Management Exposure", "Medium", 58, "CWE-200",
        "/projects.json?limit=5", 200,
        "\"projects\"", "\"identifier\"",
        ""
    },
    {
        "NVT-APP-029",
        "Exposed MediaWiki SiteInfo & Installed Extensions API",
        "Software Version Disclosure", "Low", 37, "CWE-200",
        "/api.php?action=query&meta=siteinfo&format=json", 200,
        "\"generator\"", "\"mediawiki",
        ""
    },
    {
        "NVT-INFRA-030",
        "Exposed Neo4j Graph Database Discovery Endpoint",
        "Database / Graph Exposure", "Medium", 53, "CWE-200",
        "/", 200,
        "\"bolt_direct\"", "\"neo4j_version\"",
        ""
    },
    {
        "NVT-APP-031",
        "Exposed Node.js Application Manifest (package.json)",
        "Dependency & Version Disclosure", "Low", 37, "CWE-200",
        "/package.json", 200,
        "\"dependencies\"", "\"version\"",
        ""
    },
    {
        "NVT-APP-032",
        "Exposed Roundcube Webmail Setup Installer (/installer/)",
        "Administrative Setup Exposure", "High", 82, "CWE-284",
        "/installer/", 200,
        "roundcube webmail installer", "check environment",
        ""
    },
    {
        "NVT-APP-033",
        "Exposed Strapi Headless CMS Initialization Status",
        "CMS Control-Plane Exposure", "Medium", 53, "CWE-200",
        "/admin/init", 200,
        "\"data\"", "\"hasadmin\"",
        ""
    },
    {
        "NVT-APP-034",
        "Exposed Ghost CMS Public Settings & Version API",
        "CMS Metadata Exposure", "Low", 37, "CWE-200",
        "/ghost/api/admin/site/", 200,
        "\"site\"", "\"version\"",
        ""
    },
    {
        "NVT-INFRA-035",
        "Exposed Proxmox VE Cluster Version & Node API",
        "Hypervisor Control-Plane Exposure", "Medium", 53, "CWE-200",
        "/api2/json/version", 200,
        "\"data\"", "\"release\"",
        ""
    },
    {
        "NVT-APP-036",
        "Exposed GraphQL Interactive Playground / GraphiQL IDE",
        "API Development Console Exposure", "Medium", 53, "CWE-489",
        "/graphql", 200,
        "graphql", "graphiql",
        ""
    },
    {
        "NVT-APP-037",
        "Exposed FastAPI / OpenAPI Interactive Schema (/openapi.json)",
        "API Schema Exposure", "Low", 37, "CWE-200",
        "/openapi.json", 200,
        "\"openapi\"", "\"paths\"",
        ""
    },
    {
        "NVT-INFRA-038",
        "Exposed Envoy Proxy Admin Runtime Interface",
        "Service Mesh Control-Plane Exposure", "Critical", 91, "CWE-306",
        "/server_info", 200,
        "\"version\"", "\"uptime_current_epoch\"",
        ""
    },
    {
        "NVT-APP-039",
        "Exposed WordPress Core Readme Version File (/readme.html)",
        "Software Version Disclosure", "Low", 31, "CWE-200",
        "/readme.html", 200,
        "wordpress", "famous 5-minute install",
        ""
    },
    {
        "NVT-APP-040",
        "Exposed Django Debug URLconf Route Table",
        "Debug Mode Exposure", "High", 75, "CWE-489",
        "/__debug__/", 200,
        "djdt", "django debug toolbar",
        ""
    },
    {
        "NVT-INFRA-041",
        "Exposed Caddy Reverse-Proxy Admin Config Endpoint",
        "Reverse-Proxy Control Exposure", "Critical", 94, "CWE-306",
        "/config/", 200,
        "\"apps\"", "\"http\"",
        ""
    },
    {
        "NVT-APP-042",
        "Exposed Open Journal Systems (OJS) Version Descriptor",
        "Software Version Disclosure", "Low", 37, "CWE-200",
        "/dbscripts/xml/version.xml", 200,
        "<version>", "<application>ojs2</application>",
        ""
    },
    {
        "NVT-GW-043",
        "Unauthenticated Kong API Gateway Admin Root Endpoint",
        "API Gateway Control-Plane Exposure", "Critical", 96, "CWE-306",
        "/", 200,
        "\"plugins\"", "\"available_on_server\"",
        ""
    },
    {
        "NVT-GW-044",
        "Exposed Apache APISIX Control API Schema & Health",
        "API Gateway Control-Plane Exposure", "High", 82, "CWE-306",
        "/v1/schema", 200,
        "\"main\"", "\"plugins\"",
        ""
    },
    {
        "NVT-DATA-045",
        "Exposed Apache Airflow REST API Config Endpoint",
        "Workflow Orchestrator Exposure", "High", 82, "CWE-200",
        "/api/v1/config", 200,
        "\"sections\"", "\"core\"",
        ""
    },
    {
        "NVT-DATA-046",
        "Exposed Metabase BI Public Session Properties & Setup Token",
        "BI Platform Configuration Exposure", "High", 86, "CWE-200",
        "/api/session/properties", 200,
        "\"setup-token\"", "\"version\"",
        ""
    },
    {
        "NVT-DATA-047",
        "Unauthenticated Apache Kafka Connect REST Workers API",
        "Event Streaming Control Exposure", "Critical", 91, "CWE-306",
        "/connectors", 200,
        "[", "",
        ""
    },
    {
        "NVT-DATA-048",
        "Exposed Apache ActiveMQ Web Console Broker Overview",
        "Message Broker Exposure", "High", 82, "CWE-306",
        "/admin/index.jsp", 200,
        "broker", "activemq",
        ""
    },
    {
        "NVT-INFRA-049",
        "Exposed uWSGI Application Server Stats Socket Over HTTP",
        "Infrastructure Telemetry Exposure", "Medium", 58, "CWE-200",
        "/", 200,
        "\"workers\"", "\"load\"",
        ""
    },
    {
        "NVT-INFRA-050",
        "Exposed PowerDNS Authoritative HTTP API Servers List",
        "DNS Control-Plane Exposure", "High", 78, "CWE-306",
        "/api/v1/servers", 200,
        "\"daemon_type\"", "\"config_url\"",
        ""
    },
    {
        "NVT-APP-051",
        "Exposed Apache Superset Health & Version Endpoint",
        "BI Platform Configuration Exposure", "Low", 37, "CWE-200",
        "/api/v1/security/csrf_token/", 200,
        "\"result\"", "",
        ""
    },
    {
        "NVT-APP-052",
        "Exposed Drupal CHANGELOG Version File (/CHANGELOG.txt)",
        "Software Version Disclosure", "Low", 37, "CWE-200",
        "/CHANGELOG.txt", 200,
        "drupal", "=====",
        ""
    },
    {
        "NVT-APP-053",
        "Exposed Joomla XML Extension Manifest (/administrator/manifests/files/"
        "joomla.xml)",
        "Software Version Disclosure", "Low", 37, "CWE-200",
        "/administrator/manifests/files/joomla.xml", 200,
        "<extension", "<version>",
        ""
    },
    {
        "NVT-INFRA-054",
        "Exposed Squid Proxy Cache Manager Info (/squid-internal-mgr/info)",
        "Proxy Telemetry Exposure", "Medium", 58, "CWE-200",
        "/squid-internal-mgr/info", 200,
        "squid object cache:", "connection information",
        ""
    },
    {
        "NVT-DEVOPS-055",
        "Exposed Sonatype Nexus 3 Status & System Check API",
        "Artifact Repository Exposure", "Low", 37, "CWE-200",
        "/service/rest/v1/status/check", 200,
        "\"healthy\"", "",
        ""
    },
    {
        "NVT-DEVOPS-056",
        "Exposed Jenkins Prometheus Metrics Endpoint (/prometheus/)",
        "CI/CD Telemetry Exposure", "Medium", 58, "CWE-200",
        "/prometheus/", 200,
        "default_jenkins_builds_", "jenkins_version",
        ""
    },
    {
        "NVT-INFRA-057",
        "Exposed Apache Server-Info Configuration Dump (/server-info)",
        "Sensitive Configuration Exposure", "High", 75, "CWE-200",
        "/server-info", 200,
        "apache server information", "server settings",
        ""
    },
    {
        "NVT-APP-058",
        "Exposed Spring Boot Actuator Beans Dependency Graph (/actuator/beans)",
        "Internal Architecture Exposure", "Medium", 58, "CWE-200",
        "/actuator/beans", 200,
        "\"contexts\"", "\"beans\"",
        ""
    },
    {
        "NVT-APP-059",
        "Exposed Ruby on Rails Routing Table (/rails/info/routes)",
        "Debug Mode Exposure", "High", 75, "CWE-489",
        "/rails/info/routes", 200,
        "helper", "http verb",
        ""
    },
    {
        "NVT-INFRA-060",
        "Exposed Kubernetes API Server Unauthenticated Discovery (/api)",
        "Container / Cluster Exposure", "High", 78, "CWE-306",
        "/api", 200,
        "\"kind\"", "\"apiversions\"",
        ""
    },
    {
        "NVT-AI-061",
        "Unauthenticated Ollama LLM Inference & Models API",
        "AI / ML Infrastructure Exposure", "Critical", 94, "CWE-306",
        "/api/tags", 200,
        "\"models\"", "",
        ""
    },
    {
        "NVT-AI-062",
        "Unauthenticated vLLM / OpenAI-Compatible Model Serving API",
        "AI / ML Infrastructure Exposure", "High", 86, "CWE-306",
        "/v1/models", 200,
        "\"object\"", "\"list\"",
        ""
    },
    {
        "NVT-AI-063",
        "Unauthenticated MLflow Experiment Tracking Registry API",
        "AI / ML Infrastructure Exposure", "Critical", 93, "CWE-306",
        "/ajax-api/2.0/mlflow/experiments/search?max_results=5", 200,
        "\"experiments\"", "",
        ""
    },
    {
        "NVT-AI-064",
        "Unauthenticated Ray Distributed Compute Cluster Dashboard",
        "AI / ML Infrastructure Exposure", "Critical", 98, "CWE-306",
        "/api/version", 200,
        "\"ray_version\"", "\"python_version\"",
        ""
    },
    {
        "NVT-AI-065",
        "Unauthenticated Jupyter Server Running Kernels API",
        "AI / ML Infrastructure Exposure", "Critical", 98, "CWE-306",
        "/api/kernelspecs", 200,
        "\"default\"", "\"kernelspecs\"",
        ""
    },
    {
        "NVT-AI-066",
        "Unauthenticated Qdrant Vector Database Collections API",
        "Vector Database Exposure", "Critical", 91, "CWE-306",
        "/collections", 200,
        "\"result\"", "\"collections\"",
        ""
    },
    {
        "NVT-AI-067",
        "Unauthenticated ChromaDB Vector Store Tenant API",
        "Vector Database Exposure", "High", 86, "CWE-306",
        "/api/v1/collections", 200,
        "[", "",
        ""
    },
    {
        "NVT-AI-068",
        "Unauthenticated Weaviate Vector Search Schema Endpoint",
        "Vector Database Exposure", "High", 86, "CWE-306",
        "/v1/schema", 200,
        "\"classes\"", "",
        ""
    },
    {
        "NVT-DEVOPS-069",
        "Unauthenticated Celery Flower Task Queue Monitor",
        "Queue / Worker Control Exposure", "High", 86, "CWE-306",
        "/api/workers", 200,
        "\"active_queues\"", "\"stats\"",
        ""
    },
    {
        "NVT-INFRA-070",
        "Exposed Nominatim /Meilisearch Unauthenticated Indexes API",
        "Search Database Exposure", "High", 82, "CWE-306",
        "/indexes", 200,
        "\"results\"", "\"uid\"",
        ""
    },
    {
        "NVT-DATA-071",
        "Unauthenticated Apache Flink Cluster Overview & JobManager API",
        "Distributed Compute Exposure", "Critical", 96, "CWE-306",
        "/overview", 200,
        "\"taskmanagers\"", "\"flink-version\"",
        ""
    },
    {
        "NVT-DATA-072",
        "Unauthenticated Apache Spark Standalone Master JSON API",
        "Distributed Compute Exposure", "Critical", 94, "CWE-306",
        "/json/", 200,
        "\"workers\"", "\"activeapps\"",
        ""
    },
    {
        "NVT-INFRA-073",
        "Unauthenticated HashiCorp Nomad Cluster Agent Self API",
        "Cluster Orchestrator Exposure", "Critical", 94, "CWE-306",
        "/v1/agent/self", 200,
        "\"config\"", "\"member\"",
        ""
    },
    {
        "NVT-DEVOPS-074",
        "Unauthenticated Temporal Workflow Namespaces API",
        "Workflow Orchestrator Exposure", "High", 81, "CWE-306",
        "/api/v1/namespaces", 200,
        "\"namespaces\"", "",
        ""
    },
    {
        "NVT-INFRA-075",
        "Exposed NATS Message Broker Server Monitoring (/varz)",
        "Message Broker Telemetry Exposure", "Medium", 65, "CWE-200",
        "/varz", 200,
        "\"server_id\"", "\"version\"",
        ""
    },
    {
        "NVT-DEVOPS-076",
        "Publicly Accessible Verdaccio Private NPM Registry Packages",
        "Artifact Repository Exposure", "High", 75, "CWE-200",
        "/-/verdaccio/data/packages", 200,
        "\"name\"", "\"version\"",
        ""
    },
    {
        "NVT-DEVOPS-077",
        "Exposed JFrog Artifactory System Version & Storage Info",
        "Artifact Repository Exposure", "Medium", 53, "CWE-200",
        "/artifactory/api/system/version", 200,
        "\"version\"", "\"revision\"",
        ""
    },
    {
        "NVT-INFRA-078",
        "Exposed Grafana Loki Log Aggregation BuildInfo API",
        "Monitoring / SIEM Exposure", "Medium", 58, "CWE-200",
        "/loki/api/v1/status/buildinfo", 200,
        "\"version\"", "\"branch\"",
        ""
    },
    {
        "NVT-INFRA-079",
        "Exposed VictoriaMetrics Runtime Command-Line Flags (/flags)",
        "Sensitive Configuration Exposure", "Medium", 65, "CWE-200",
        "/flags", 200,
        "-storageDataPath", "-httpListenAddr",
        ""
    },
    {
        "NVT-DATA-080",
        "Unauthenticated Airbyte Data Integration Workspaces API",
        "Data Pipeline Control Exposure", "Critical", 91, "CWE-306",
        "/api/v1/workspaces/list", 200,
        "\"workspaces\"", "",
        ""
    },
    {
        "NVT-INFRA-081",
        "Exposed SUSE Rancher Kubernetes Management Settings API",
        "Cluster Orchestrator Exposure", "Medium", 58, "CWE-200",
        "/v3/settings/server-version", 200,
        "\"baseType\"", "\"setting\"",
        ""
    },
    {
        "NVT-INFRA-082",
        "Unauthenticated Longhorn Distributed Block Storage Volumes API",
        "Storage Control-Plane Exposure", "Critical", 94, "CWE-306",
        "/v1/volumes", 200,
        "\"resourceType\"", "\"volume\"",
        ""
    },
    {
        "NVT-INFRA-083",
        "Exposed Ceph Storage Cluster Dashboard Health API",
        "Storage Control-Plane Exposure", "High", 78, "CWE-306",
        "/api/summary", 200,
        "\"health_status\"", "\"mgr_host\"",
        ""
    },
    {
        "NVT-INFRA-084",
        "Exposed Webmin / Usermin Linux Administration Login Surface",
        "Administrative Interface Exposure", "Medium", 58, "CWE-284",
        "/", 200,
        "webmin", "session_login",
        ""
    },
    {
        "NVT-INFRA-085",
        "Exposed Red Hat / Ubuntu Cockpit Server Console (/cockpit/login)",
        "Administrative Interface Exposure", "Medium", 53, "CWE-284",
        "/cockpit/login", 200,
        "cockpit", "login-user-input",
        ""
    },
    {
        "NVT-DEVOPS-086",
        "Exposed Graylog SIEM Cluster System Node Info API",
        "Monitoring / SIEM Exposure", "Medium", 53, "CWE-200",
        "/api/system/cluster/node", 200,
        "\"cluster_id\"", "\"node_id\"",
        ""
    },
    {
        "NVT-DEVOPS-087",
        "Unauthenticated OpenSearch Dashboards Status Telemetry",
        "Monitoring / SIEM Exposure", "High", 75, "CWE-306",
        "/api/status", 200,
        "\"version\"", "\"opensearch\"",
        ""
    },
    {
        "NVT-DATA-088",
        "Unauthenticated Dagster Data Orchestrator GraphQL IDE",
        "Data Pipeline Control Exposure", "Critical", 91, "CWE-306",
        "/server_info", 200,
        "\"dagster_version\"", "",
        ""
    },
    {
        "NVT-DATA-089",
        "Unauthenticated Prefect Workflow Server API Health & Version",
        "Data Pipeline Control Exposure", "High", 82, "CWE-306",
        "/api/admin/version", 200,
        "2.", "",
        ""
    },
    {
        "NVT-DEVOPS-090",
        "Exposed n8n Workflow Automation Public Settings Endpoint",
        "Workflow Automation Exposure", "Medium", 58, "CWE-200",
        "/rest/settings", 200,
        "\"data\"", "\"versionCli\"",
        ""
    },
    {
        "NVT-APP-091",
        "Exposed Keycloak Master Realm Admin Console Info",
        "IAM Control-Plane Exposure", "Medium", 53, "CWE-200",
        "/realms/master", 200,
        "\"realm\"", "\"master\"",
        ""
    },
    {
        "NVT-INFRA-092",
        "Exposed Plesk Server Control Panel Login Interface",
        "Administrative Interface Exposure", "Low", 37, "CWE-284",
        "/login_up.php", 200,
        "plesk", "login_name",
        ""
    },
    {
        "NVT-INFRA-093",
        "Exposed cPanel / WHM Server Administration Login",
        "Administrative Interface Exposure", "Low", 37, "CWE-284",
        "/", 200,
        "cpanel", "login",
        ""
    },
    {
        "NVT-DB-094",
        "Exposed ClickHouse Web SQL Playground (/play)",
        "Database Control-Plane Exposure", "Medium", 65, "CWE-284",
        "/play", 200,
        "clickhouse", "run-query",
        ""
    },
    {
        "NVT-DEVOPS-095",
        "Exposed Prometheus Alertmanager Active Alerts API",
        "Monitoring / SIEM Exposure", "Medium", 58, "CWE-200",
        "/api/v2/alerts", 200,
        "\"annotations\"", "\"fingerprint\"",
        ""
    },
    {
        "NVT-DEVOPS-096",
        "Exposed Jaeger Distributed Tracing Services Topology API",
        "Microservice Topology Exposure", "Medium", 58, "CWE-200",
        "/api/services", 200,
        "\"data\"", "\"total\"",
        ""
    },
    {
        "NVT-DEVOPS-097",
        "Exposed Zipkin Distributed Tracing Services List",
        "Microservice Topology Exposure", "Medium", 58, "CWE-200",
        "/zipkin/api/v2/services", 200,
        "[", "",
        ""
    },
    {
        "NVT-APP-098",
        "Exposed Moodle Environment Compatibility Matrix (/admin/environment.xm"
        "l)",
        "Software Version Disclosure", "Low", 37, "CWE-200",
        "/admin/environment.xml", 200,
        "<compatibility_matrix>", "moodle",
        ""
    },
    {
        "NVT-APP-099",
        "Exposed Uptime Kuma Public Status Page Heartbeat API",
        "Infrastructure Telemetry Exposure", "Low", 37, "CWE-200",
        "/api/entry-page", 200,
        "\"type\"", "",
        ""
    },
    {
        "NVT-INFRA-100",
        "Unauthenticated Go pprof Runtime Profiling Index (/debug/pprof/)",
        "Runtime Memory & Goroutine Exposure", "High", 75, "CWE-200",
        "/debug/pprof/", 200,
        "types of profiles available:", "goroutine",
        ""
    },
    {
        "NVT-INFRA-101",
        "Exposed Envoy Proxy Upstream Clusters Telemetry (/clusters)",
        "Reverse-Proxy Control Exposure", "Medium", 65, "CWE-200",
        "/clusters", 200,
        "::health_flags::", "::weight::",
        ""
    },
    {
        "NVT-INFRA-102",
        "Unauthenticated Envoy Proxy Runtime Config Dump (/config_dump)",
        "Reverse-Proxy Control Exposure", "High", 75, "CWE-200",
        "/config_dump", 200,
        "\"configs\"", "\"bootstrap\"",
        ""
    },
    {
        "NVT-INFRA-103",
        "Unauthenticated Caddy Server Admin REST API (/config/)",
        "Reverse-Proxy Control Exposure", "Critical", 91, "CWE-306",
        "/config/", 200,
        "\"apps\"", "\"http\"",
        ""
    },
    {
        "NVT-DEVOPS-104",
        "Exposed ArgoCD GitOps Server Build & Version API (/api/version)",
        "DevOps Control-Plane Exposure", "Low", 37, "CWE-200",
        "/api/version", 200,
        "\"version\"", "\"kustomizeversion\"",
        ""
    },
    {
        "NVT-DEVOPS-105",
        "Exposed Kubernetes Web Dashboard CSRF Login API",
        "Container Management Exposure", "Medium", 58, "CWE-284",
        "/api/v1/csrftoken/login", 200,
        "\"token\"", "",
        ""
    },
    {
        "NVT-DEVOPS-106",
        "Unauthenticated Netdata Host System Telemetry (/api/v1/info)",
        "Infrastructure Telemetry Exposure", "Medium", 58, "CWE-200",
        "/api/v1/info", 200,
        "\"mirrored_hosts\"", "\"os_name\"",
        ""
    },
    {
        "NVT-DEVOPS-107",
        "Unauthenticated Glances System Monitor Memory API (/api/3/mem)",
        "Infrastructure Telemetry Exposure", "Medium", 58, "CWE-306",
        "/api/3/mem", 200,
        "\"total\"", "\"available\"",
        ""
    },
    {
        "NVT-DEVOPS-108",
        "Unauthenticated Supervisord Process Control Dashboard",
        "Process Control Exposure", "Critical", 96, "CWE-306",
        "/index.html", 200,
        "supervisor status", "restart all",
        ""
    },
    {
        "NVT-DATA-109",
        "Exposed Milvus Vector Database Metrics Endpoint (/metrics)",
        "AI / Vector DB Exposure", "Medium", 53, "CWE-200",
        "/metrics", 200,
        "milvus_", "# help",
        ""
    },
    {
        "NVT-DATA-110",
        "Exposed Neo4j Graph Database Discovery & Bolt Routing Endpoint",
        "Database Control-Plane Exposure", "Low", 37, "CWE-200",
        "/", 200,
        "\"bolt_direct\"", "\"neo4j_version\"",
        ""
    },
    {
        "NVT-DATA-111",
        "Exposed CockroachDB Node Runtime Variables (/_status/vars)",
        "Database Control-Plane Exposure", "Medium", 58, "CWE-200",
        "/_status/vars", 200,
        "go_goroutines", "sql_conns",
        ""
    },
    {
        "NVT-DATA-112",
        "Unauthenticated QuestDB HTTP SQL Execution Interface (/exec)",
        "Database / Cache Exposure", "Critical", 94, "CWE-306",
        "/exec?query=select+1", 200,
        "\"query\"", "\"columns\"",
        ""
    },
    {
        "NVT-DATA-113",
        "Unauthenticated Redpanda Streaming Admin API (/v1/cluster_config_statu"
        "s)",
        "Streaming / Queue Exposure", "High", 75, "CWE-306",
        "/v1/cluster_config_status", 200,
        "\"config_version\"", "",
        ""
    },
    {
        "NVT-DATA-114",
        "Unauthenticated Apache Druid Cluster Status & Loaded Modules (/status)",
        "Analytics Cluster Exposure", "Medium", 58, "CWE-200",
        "/status", 200,
        "\"version\"", "\"modules\"",
        ""
    },
    {
        "NVT-DATA-115",
        "Unauthenticated Apache Pinot Controller Tables API (/tables)",
        "Analytics Cluster Exposure", "High", 75, "CWE-306",
        "/tables", 200,
        "\"tables\"", "",
        ""
    },
    {
        "NVT-AI-116",
        "Exposed BentoML Inference Server Metrics (/metrics)",
        "AI / ML Model Serving Exposure", "Low", 37, "CWE-200",
        "/metrics", 200,
        "bentoml_", "# type",
        ""
    },
    {
        "NVT-AI-117",
        "Unauthenticated NVIDIA Triton Inference Server v2 Metadata (/v2)",
        "AI / ML Model Serving Exposure", "Medium", 65, "CWE-306",
        "/v2", 200,
        "\"name\"", "\"version\"",
        ""
    },
    {
        "NVT-AI-118",
        "Exposed Gradio ML Application Component & Dependency Config (/config)",
        "AI / ML Application Exposure", "Medium", 53, "CWE-200",
        "/config", 200,
        "\"components\"", "\"dependencies\"",
        ""
    },
    {
        "NVT-AI-119",
        "Unauthenticated Langflow AI Auto-Login Token Issuance (/api/v1/auto_lo"
        "gin)",
        "AI / ML Control-Plane Bypass", "Critical", 98, "CWE-306",
        "/api/v1/auto_login", 200,
        "\"access_token\"", "\"token_type\"",
        ""
    },
    {
        "NVT-AI-120",
        "Unauthenticated Flowise AI Agent Chatflows Inventory (/api/v1/chatflow"
        "s)",
        "AI / ML Control-Plane Bypass", "High", 86, "CWE-306",
        "/api/v1/chatflows", 200,
        "\"flowdata\"", "\"deployed\"",
        ""
    },
    {
        "NVT-AI-121",
        "Unauthenticated ComfyUI GPU & System Stats Endpoint (/system_stats)",
        "AI / ML Application Exposure", "High", 75, "CWE-306",
        "/system_stats", 200,
        "\"system\"", "\"devices\"",
        ""
    },
    {
        "NVT-AI-122",
        "Exposed Open WebUI System Configuration & Version (/api/config)",
        "AI / ML Application Exposure", "Low", 37, "CWE-200",
        "/api/config", 200,
        "\"version\"", "\"default_models\"",
        ""
    },
    {
        "NVT-APP-123",
        "Unauthenticated Spring Boot Actuator ThreadDump Exposure (/actuator/th"
        "readdump)",
        "Sensitive Environment Exposure", "High", 75, "CWE-200",
        "/actuator/threaddump", 200,
        "\"threads\"", "\"threadname\"",
        ""
    },
    {
        "NVT-APP-124",
        "Exposed Spring Boot Actuator Scheduled Tasks (/actuator/scheduledtasks"
        ")",
        "Sensitive Environment Exposure", "Medium", 53, "CWE-200",
        "/actuator/scheduledtasks", 200,
        "\"cron\"", "\"fixeddelay\"",
        ""
    },
    {
        "NVT-APP-125",
        "Unauthenticated ASP.NET ELMAH Error Log Console (/elmah.axd)",
        "Debug / Error Log Exposure", "High", 75, "CWE-532",
        "/elmah.axd", 200,
        "error log for", "powered by elmah",
        ""
    },
    {
        "NVT-APP-126",
        "Unauthenticated ASP.NET Request Trace Viewer (/trace.axd)",
        "Debug / Error Log Exposure", "High", 75, "CWE-200",
        "/trace.axd", 200,
        "application trace", "request limit",
        ""
    },
    {
        "NVT-APP-127",
        "Exposed PocketBase Backend Health & API Surface (/api/health)",
        "Backend API Telemetry", "Low", 37, "CWE-200",
        "/api/health", 200,
        "\"code\"", "\"message\"",
        ""
    },
    {
        "NVT-APP-128",
        "Exposed PostgREST / Supabase Database Table Schema (/rest/v1/)",
        "Database Schema Disclosure", "Medium", 53, "CWE-200",
        "/rest/v1/", 200,
        "\"swagger\"", "\"postgrest\"",
        ""
    },
    {
        "NVT-APP-129",
        "Unauthenticated MinIO Node Prometheus Metrics (/minio/v2/metrics/node)",
        "Object Storage Telemetry Exposure", "Medium", 53, "CWE-200",
        "/minio/v2/metrics/node", 200,
        "minio_node_", "# help",
        ""
    },
    {
        "NVT-APP-130",
        "Unauthenticated HashiCorp Consul Cluster Members API (/v1/agent/member"
        "s)",
        "Service Mesh Control Exposure", "High", 75, "CWE-306",
        "/v1/agent/members", 200,
        "\"name\"", "\"addr\"",
        ""
    },
    {
        "NVT-DEVOPS-131",
        "Exposed Wazuh SIEM Manager REST API Metadata",
        "Monitoring / SIEM Exposure", "Low", 37, "CWE-200",
        "/", 200,
        "\"wazuh api\"", "\"api_version\"",
        ""
    },
    {
        "NVT-DEVOPS-132",
        "Exposed SonarQube Server Version & System Status (/api/system/status)",
        "DevOps Control-Plane Exposure", "Low", 37, "CWE-200",
        "/api/system/status", 200,
        "\"id\"", "\"version\"",
        ""
    },
    {
        "NVT-DEVOPS-133",
        "Exposed Sonatype Nexus Public Repository Component Listing",
        "Artifact Registry Exposure", "Medium", 53, "CWE-200",
        "/service/rest/v1/components?repository=maven-public", 200,
        "\"items\"", "\"continuationtoken\"",
        ""
    },
    {
        "NVT-DEVOPS-134",
        "Unauthenticated Jenkins Groovy Script Console (/script)",
        "CI/CD Remote Execution Surface", "Critical", 98, "CWE-306",
        "/script", 200,
        "script console", "type in an arbitrary groovy script",
        ""
    },
    {
        "NVT-APP-135",
        "Exposed Hasura GraphQL Engine Version Endpoint (/v1/version)",
        "Backend API Telemetry", "Low", 37, "CWE-200",
        "/v1/version", 200,
        "\"version\"", "",
        ""
    },
    {
        "NVT-APP-136",
        "Exposed Appsmith Internal Tool Builder Health API (/api/v1/health)",
        "Low-Code Platform Telemetry", "Low", 37, "CWE-200",
        "/api/v1/health", 200,
        "\"responsemeta\"", "\"status\"",
        ""
    },
    {
        "NVT-APP-137",
        "Exposed NocoDB Database Platform Metadata (/api/v1/db/meta/nocoinfo)",
        "Database Control-Plane Exposure", "Low", 37, "CWE-200",
        "/api/v1/db/meta/nocoinfo", 200,
        "\"version\"", "\"authtype\"",
        ""
    },
    {
        "NVT-DATA-138",
        "Unauthenticated Typesense Search Engine Metrics (/metrics.json)",
        "Database / Search Telemetry", "Medium", 53, "CWE-306",
        "/metrics.json", 200,
        "\"system_cpu_active_percentage\"", "\"typesense_memory\"",
        ""
    },
    {
        "NVT-DATA-139",
        "Unauthenticated SeaweedFS Distributed Storage Topology (/dir/status)",
        "Object Storage Control Exposure", "High", 75, "CWE-306",
        "/dir/status", 200,
        "\"topology\"", "\"version\"",
        ""
    },
    {
        "NVT-DEVOPS-140",
        "Unauthenticated Apache NiFi System Diagnostics (/nifi-api/system-diagn"
        "ostics)",
        "Data Pipeline Control Exposure", "High", 75, "CWE-306",
        "/nifi-api/system-diagnostics", 200,
        "\"systemdiagnostics\"", "\"aggregatesnapshot\"",
        ""
    },
    {
        "NVT-DEVOPS-141",
        "Unauthenticated Rundeck System Info API (/api/41/system/info)",
        "DevOps Control-Plane Exposure", "High", 75, "CWE-306",
        "/api/41/system/info", 200,
        "\"system\"", "\"rundeck\"",
        ""
    },
    {
        "NVT-DEVOPS-142",
        "Exposed Woodpecker CI Server Version Metadata (/version)",
        "CI/CD Telemetry Exposure", "Low", 37, "CWE-200",
        "/version", 200,
        "\"version\"", "\"woodpecker\"",
        ""
    },
    {
        "NVT-DEVOPS-143",
        "Unauthenticated Drone CI Build Queue Exposure (/api/queue)",
        "CI/CD Control-Plane Exposure", "High", 75, "CWE-306",
        "/api/queue", 200,
        "\"stage\"", "\"machine\"",
        ""
    },
    {
        "NVT-APP-144",
        "Exposed Outline Knowledge Base SSO Providers Config (/api/auth.config)",
        "IAM & SSO Architecture", "Low", 37, "CWE-200",
        "/api/auth.config", 200,
        "\"data\"", "\"providers\"",
        ""
    },
    {
        "NVT-APP-145",
        "Unauthenticated Keycloak Admin Server Info (/admin/serverinfo)",
        "IAM Control-Plane Exposure", "High", 82, "CWE-306",
        "/admin/serverinfo", 200,
        "\"systeminfo\"", "\"memoryinfo\"",
        ""
    },
    {
        "NVT-DATA-146",
        "Exposed VictoriaMetrics Scrape Targets Inventory (/targets)",
        "Infrastructure Telemetry Exposure", "Medium", 58, "CWE-200",
        "/targets", 200,
        "endpoint=", "state=",
        ""
    },
    {
        "NVT-DATA-147",
        "Unauthenticated Thanos Query Stores Topology (/api/v1/stores)",
        "Monitoring / SIEM Exposure", "Medium", 58, "CWE-200",
        "/api/v1/stores", 200,
        "\"status\"", "\"data\"",
        ""
    },
    {
        "NVT-DEVOPS-148",
        "Unauthenticated Harbor Container Registry System Config (/api/v2.0/con"
        "figurations)",
        "Container Registry Exposure", "High", 75, "CWE-306",
        "/api/v2.0/configurations", 200,
        "\"auth_mode\"", "\"self_registration\"",
        ""
    },
    {
        "NVT-APP-149",
        "Exposed PHP OPcache Diagnostic Status Dashboard (/opcache.php)",
        "Runtime Memory & Script Path Exposure", "Medium", 58, "CWE-200",
        "/opcache.php", 200,
        "opcache", "memory_usage",
        ""
    },
    {
        "NVT-INFRA-150",
        "Unauthenticated Node.js V8 Inspector Debugger Endpoint (/json/version)",
        "Runtime Debugger Exposure", "Critical", 98, "CWE-489",
        "/json/version", 200,
        "\"protocol-version\"", "\"websocketdebuggerurl\"",
        ""
    },
    {
        "NVT-AI-151",
        "Unauthenticated LiteLLM Gateway Model Info (/model/info)",
        "AI / LLM Gateway Exposure", "High", 75, "CWE-306",
        "/model/info", 200,
        "\"data\"", "\"litellm_params\"",
        ""
    },
    {
        "NVT-AI-152",
        "Unauthenticated LocalAI Models Inventory (/models/available)",
        "AI / LLM Gateway Exposure", "High", 75, "CWE-306",
        "/models/available", 200,
        "\"urls\"", "\"license\"",
        ""
    },
    {
        "NVT-AI-153",
        "Exposed OpenWebUI Configuration (/api/config)",
        "AI / LLM Platform Telemetry", "Medium", 53, "CWE-200",
        "/api/config", 200,
        "\"enable_signup\"", "\"default_models\"",
        ""
    },
    {
        "NVT-AI-154",
        "Exposed Dify Setup Status (/console/api/setup)",
        "AI / LLM Platform Telemetry", "Medium", 53, "CWE-200",
        "/console/api/setup", 200,
        "\"step\"", "",
        ""
    },
    {
        "NVT-AI-155",
        "Unauthenticated BentoML Service Schema (/docs.json)",
        "AI / ML Service Exposure", "Medium", 53, "CWE-200",
        "/docs.json", 200,
        "\"bentoml\"", "\"paths\"",
        ""
    },
    {
        "NVT-GW-156",
        "Unauthenticated Envoy Admin Clusters (/clusters)",
        "API Gateway Control Exposure", "High", 82, "CWE-306",
        "/clusters", 200,
        "::cx_active::", "::rq_total::",
        ""
    },
    {
        "NVT-GW-157",
        "Unauthenticated Caddy Admin Config API (/config/)",
        "API Gateway Control Exposure", "Critical", 98, "CWE-306",
        "/config/", 200,
        "\"apps\"", "\"http\"",
        ""
    },
    {
        "NVT-GW-158",
        "Unauthenticated Kong Admin Services List (/services)",
        "API Gateway Control Exposure", "Critical", 91, "CWE-306",
        "/services", 200,
        "\"data\"", "\"connect_timeout\"",
        ""
    },
    {
        "NVT-GW-159",
        "Exposed KrakenD Stats Endpoint (/__stats/)",
        "API Gateway Telemetry Exposure", "Medium", 53, "CWE-200",
        "/__stats/", 200,
        "\"cmdline\"", "\"memstats\"",
        ""
    },
    {
        "NVT-GW-160",
        "Exposed Tyk Gateway Telemetry (/hello)",
        "API Gateway Telemetry Exposure", "Low", 37, "CWE-200",
        "/hello", 200,
        "\"status\"", "\"version\"",
        ""
    },
    {
        "NVT-DEVOPS-161",
        "Exposed HashiCorp Vault Seal Status (/v1/sys/seal-status)",
        "Secrets Manager Telemetry", "Low", 37, "CWE-200",
        "/v1/sys/seal-status", 200,
        "\"sealed\"", "\"cluster_name\"",
        ""
    },
    {
        "NVT-DEVOPS-162",
        "Unauthenticated HashiCorp Consul Agent Config (/v1/agent/self)",
        "Service Mesh Control Exposure", "High", 82, "CWE-306",
        "/v1/agent/self", 200,
        "\"Config\"", "\"Datacenter\"",
        ""
    },
    {
        "NVT-DEVOPS-163",
        "Exposed Sonatype Nexus Repositories API (/service/rest/v1/repositories"
        ")",
        "Artifact Registry Exposure", "Medium", 58, "CWE-200",
        "/service/rest/v1/repositories", 200,
        "\"format\"", "\"type\"",
        ""
    },
    {
        "NVT-DEVOPS-164",
        "Unauthenticated OpenTelemetry zPages (/debug/tracez)",
        "Observability Telemetry Exposure", "Medium", 58, "CWE-200",
        "/debug/tracez", 200,
        "zpages", "latencysamples",
        ""
    },
    {
        "NVT-DEVOPS-165",
        "Exposed Grafana Pyroscope Build Info (/build)",
        "Observability Telemetry Exposure", "Low", 37, "CWE-200",
        "/build", 200,
        "\"goos\"", "\"version\"",
        ""
    },
    {
        "NVT-DATA-166",
        "Unauthenticated Apache Druid Status (/status)",
        "Data Analytics Control Exposure", "High", 75, "CWE-306",
        "/status", 200,
        "\"version\"", "\"modules\"",
        ""
    },
    {
        "NVT-DATA-167",
        "Unauthenticated Apache Pinot Tables List (/tables)",
        "Data Analytics Control Exposure", "High", 75, "CWE-306",
        "/tables", 200,
        "\"tables\"", "",
        ""
    },
    {
        "NVT-DATA-168",
        "Unauthenticated Meilisearch Indexes (/indexes)",
        "Database / Search Exposure", "High", 82, "CWE-306",
        "/indexes", 200,
        "\"results\"", "\"primarykey\"",
        ""
    },
    {
        "NVT-DATA-169",
        "Exposed ClickHouse Replicas Status (/replicas_status)",
        "Database Telemetry Exposure", "Low", 37, "CWE-200",
        "/replicas_status", 200,
        "ok", "",
        ""
    },
    {
        "NVT-DATA-170",
        "Unauthenticated QuestDB SQL Execution (/exec?query=select+1)",
        "Database / SQL Exposure", "Critical", 94, "CWE-306",
        "/exec?query=select+1", 200,
        "\"query\"", "\"columns\"",
        ""
    },
    {
        "NVT-APP-171",
        "Unauthenticated PocketBase Collections Schema (/api/collections)",
        "Backend-as-a-Service Exposure", "High", 75, "CWE-306",
        "/api/collections", 200,
        "\"items\"", "\"totalitems\"",
        ""
    },
    {
        "NVT-APP-172",
        "Exposed Appwrite Health Version (/v1/health/version)",
        "Backend-as-a-Service Telemetry", "Low", 37, "CWE-200",
        "/v1/health/version", 200,
        "\"version\"", "",
        ""
    },
    {
        "NVT-APP-173",
        "Exposed Strapi Admin Init Metadata (/admin/init)",
        "CMS Control-Plane Telemetry", "Low", 37, "CWE-200",
        "/admin/init", 200,
        "\"data\"", "\"hasadmin\"",
        ""
    },
    {
        "NVT-APP-174",
        "Unauthenticated Camunda Engine REST API (/engine-rest/engine)",
        "Workflow Automation Exposure", "High", 75, "CWE-306",
        "/engine-rest/engine", 200,
        "\"name\"", "\"default\"",
        ""
    },
    {
        "NVT-APP-175",
        "Unauthenticated PostgREST / Supabase Schema Root (/rest/v1/)",
        "Database / API Schema Exposure", "Medium", 58, "CWE-200",
        "/rest/v1/", 200,
        "\"swagger\"", "\"definitions\"",
        ""
    },
    {
        "NVT-TEL-176",
        "Exposed Fluent Bit HTTP Monitoring API (/api/v1/uptime)",
        "Observability Telemetry Exposure", "High", 75, "CWE-306",
        "/api/v1/uptime", 200,
        "\"uptime_sec\"", "\"uptime_hr\"",
        ""
    },
    {
        "NVT-TEL-177",
        "Unauthenticated Vector Observability Playground (/playground)",
        "Observability Telemetry Exposure", "Medium", 58, "CWE-306",
        "/playground", 200,
        "graphql", "vector",
        ""
    },
    {
        "NVT-TEL-178",
        "Unauthenticated Jaeger Tracing Services API (/api/services)",
        "Observability Telemetry Exposure", "Medium", 58, "CWE-200",
        "/api/services", 200,
        "\"data\"", "\"total\"",
        ""
    },
    {
        "NVT-TEL-179",
        "Unauthenticated Zipkin Services Inventory (/zipkin/api/v2/services)",
        "Observability Telemetry Exposure", "Medium", 58, "CWE-200",
        "/zipkin/api/v2/services", 200,
        "[", "",
        ""
    },
    {
        "NVT-TEL-180",
        "Unauthenticated Netdata Host Telemetry (/api/v1/info)",
        "Infrastructure Telemetry Exposure", "Medium", 58, "CWE-200",
        "/api/v1/info", 200,
        "\"version\"", "\"uid\"",
        ""
    },
    {
        "NVT-IAM-181",
        "Exposed Authelia SSO Configuration (/api/configuration)",
        "IAM & SSO Architecture", "Low", 37, "CWE-200",
        "/api/configuration", 200,
        "\"status\"", "\"available_methods\"",
        ""
    },
    {
        "NVT-IAM-182",
        "Exposed Authentik Root Config (/api/v3/root/config/)",
        "IAM & SSO Architecture", "Low", 37, "CWE-200",
        "/api/v3/root/config/", 200,
        "\"capabilities\"", "\"error_reporting\"",
        ""
    },
    {
        "NVT-IAM-183",
        "Unauthenticated Ory Hydra Admin Clients (/admin/clients)",
        "IAM Control-Plane Exposure", "Critical", 91, "CWE-306",
        "/admin/clients", 200,
        "\"client_id\"", "\"grant_types\"",
        ""
    },
    {
        "NVT-IAM-184",
        "Exposed Ory Kratos Identity Schemas (/schemas)",
        "IAM & SSO Architecture", "Low", 37, "CWE-200",
        "/schemas", 200,
        "\"id\"", "\"schema\"",
        ""
    },
    {
        "NVT-IAM-185",
        "Exposed Casdoor IAM App Login Metadata (/api/get-app-login?id=admin/ap"
        "p-built-in)",
        "IAM & SSO Architecture", "Medium", 53, "CWE-200",
        "/api/get-app-login?id=admin/app-built-in", 200,
        "\"status\"", "\"enablePassword\"",
        ""
    },
    {
        "NVT-DEVOPS-186",
        "Exposed Argo Workflows Server Info (/api/v1/info)",
        "DevOps Control-Plane Exposure", "Medium", 58, "CWE-200",
        "/api/v1/info", 200,
        "\"managedNamespace\"", "",
        ""
    },
    {
        "NVT-DEVOPS-187",
        "Unauthenticated Tekton Pipelines Inventory (/v1/namespaces/default/pip"
        "elines)",
        "CI/CD Control-Plane Exposure", "High", 82, "CWE-306",
        "/v1/namespaces/default/pipelines", 200,
        "\"apiVersion\"", "\"tekton.dev\"",
        ""
    },
    {
        "NVT-DEVOPS-188",
        "Unauthenticated Spinnaker Gate Applications (/applications)",
        "CI/CD Control-Plane Exposure", "High", 86, "CWE-306",
        "/applications", 200,
        "\"name\"", "\"cloudproviders\"",
        ""
    },
    {
        "NVT-DEVOPS-189",
        "Unauthenticated GoCD Build Agents API (/go/api/agents)",
        "CI/CD Control-Plane Exposure", "High", 82, "CWE-306",
        "/go/api/agents", 200,
        "\"_embedded\"", "\"agents\"",
        ""
    },
    {
        "NVT-DEVOPS-190",
        "Unauthenticated Nomad Cluster Members (/v1/agent/members)",
        "Cluster Orchestrator Exposure", "High", 75, "CWE-306",
        "/v1/agent/members", 200,
        "\"ServerName\"", "\"Members\"",
        ""
    },
    {
        "NVT-DATA-191",
        "Unauthenticated Apache Doris Bootstrap Info (/api/bootstrap)",
        "Database Control-Plane Exposure", "Medium", 53, "CWE-200",
        "/api/bootstrap", 200,
        "\"replayedjournalid\"", "",
        ""
    },
    {
        "NVT-DATA-192",
        "Unauthenticated TiDB Server Status (/status)",
        "Database Telemetry Exposure", "Medium", 53, "CWE-200",
        "/status", 200,
        "\"connections\"", "\"version\"",
        ""
    },
    {
        "NVT-DATA-193",
        "Unauthenticated CockroachDB Cluster Nodes (/_status/nodes)",
        "Database Control-Plane Exposure", "High", 75, "CWE-306",
        "/_status/nodes", 200,
        "\"nodes\"", "\"buildInfo\"",
        ""
    },
    {
        "NVT-DATA-194",
        "Unauthenticated ScyllaDB Storage HostID (/storage_service/hostid)",
        "Database Control-Plane Exposure", "High", 82, "CWE-306",
        "/storage_service/hostid", 200,
        "\"key\"", "\"value\"",
        ""
    },
    {
        "NVT-DATA-195",
        "Unauthenticated Redpanda Cluster Config (/v1/cluster_config)",
        "Streaming / Queue Exposure", "High", 82, "CWE-306",
        "/v1/cluster_config", 200,
        "\"cluster_id\"", "\"kafka_enable_authorization\"",
        ""
    },
    {
        "NVT-APP-196",
        "Exposed Directus CMS Server Info (/server/info)",
        "CMS Control-Plane Telemetry", "Low", 37, "CWE-200",
        "/server/info", 200,
        "\"data\"", "\"project\"",
        ""
    },
    {
        "NVT-APP-197",
        "Exposed Ghost CMS Admin Site Metadata (/ghost/api/admin/site/)",
        "CMS Control-Plane Telemetry", "Low", 37, "CWE-200",
        "/ghost/api/admin/site/", 200,
        "\"site\"", "\"version\"",
        ""
    },
    {
        "NVT-APP-198",
        "Exposed Mattermost Client Config (/api/v4/config/client?format=old)",
        "Collaboration Platform Telemetry", "Low", 37, "CWE-200",
        "/api/v4/config/client?format=old", 200,
        "\"Version\"", "\"SiteName\"",
        ""
    },
    {
        "NVT-APP-199",
        "Exposed Rocket.Chat Public Settings (/api/v1/settings.public)",
        "Collaboration Platform Telemetry", "Low", 37, "CWE-200",
        "/api/v1/settings.public", 200,
        "\"settings\"", "\"count\"",
        ""
    },
    {
        "NVT-APP-200",
        "Exposed Discourse Basic Site Metadata (/site/basic-info.json)",
        "Collaboration Platform Telemetry", "Low", 37, "CWE-200",
        "/site/basic-info.json", 200,
        "\"title\"", "\"description\"",
        ""
    },
    {
        "NVT-AI-201",
        "Unauthenticated Ollama Loaded Models Memory Telemetry (/api/ps)",
        "AI / LLM Runtime Exposure", "High", 75, "CWE-306",
        "/api/ps", 200,
        "\"models\"", "\"size_vram\"",
        ""
    },
    {
        "NVT-AI-202",
        "Unauthenticated Langflow AI Pipelines Inventory (/api/v1/flows/)",
        "AI / LLM Agent Exposure", "Critical", 91, "CWE-306",
        "/api/v1/flows/", 200,
        "\"data\"", "\"is_component\"",
        ""
    },
    {
        "NVT-AI-203",
        "Unauthenticated MLflow Experiments Search API (/ajax-api/2.0/mlflow/ex"
        "periments/search)",
        "AI / ML Registry Exposure", "High", 86, "CWE-306",
        "/ajax-api/2.0/mlflow/experiments/search?max_results=5", 200,
        "\"experiments\"", "\"artifact_location\"",
        ""
    },
    {
        "NVT-AI-204",
        "Unauthenticated NVIDIA Triton Model Repository Index (/v2/repository/i"
        "ndex)",
        "AI / ML Inference Exposure", "High", 75, "CWE-306",
        "/v2/repository/index", 200,
        "\"name\"", "\"state\"",
        ""
    },
    {
        "NVT-AI-205",
        "Exposed Gradio ML Application Endpoint Specification (/gradio_api/info"
        ")",
        "AI / ML Application Telemetry", "Medium", 53, "CWE-200",
        "/gradio_api/info", 200,
        "\"named_endpoints\"", "\"unnamed_endpoints\"",
        ""
    },
    {
        "NVT-AI-206",
        "Exposed Streamlit Internal Host Configuration (/_stcore/host-config)",
        "AI / Data App Telemetry", "Low", 37, "CWE-200",
        "/_stcore/host-config", 200,
        "\"allowedOrigins\"", "",
        ""
    },
    {
        "NVT-AI-207",
        "Exposed JupyterHub REST Version Metadata (/hub/api)",
        "AI / Notebook Control Telemetry", "Low", 37, "CWE-200",
        "/hub/api", 200,
        "\"version\"", "",
        ""
    },
    {
        "NVT-AI-208",
        "Unauthenticated Milvus Vector DB Metrics (/metrics)",
        "AI / RAG Vector Store Telemetry", "Medium", 58, "CWE-200",
        "/metrics", 200,
        "milvus_proxy_", "milvus_rootcoord_",
        ""
    },
    {
        "NVT-AI-209",
        "Exposed AnythingLLM System Health Telemetry (/api/system/check)",
        "AI / RAG Platform Telemetry", "Medium", 53, "CWE-200",
        "/api/system/check", 200,
        "\"online\"", "true",
        ""
    },
    {
        "NVT-AI-210",
        "Exposed LibreChat Startup Configuration (/api/startup-config)",
        "AI / Chat Gateway Telemetry", "Low", 37, "CWE-200",
        "/api/startup-config", 200,
        "\"appTitle\"", "\"registrationEnabled\"",
        ""
    },
    {
        "NVT-CLOUD-211",
        "Unauthenticated Kubernetes kube-system Services API (/api/v1/namespace"
        "s/kube-system/services)",
        "Container Orchestrator Exposure", "Critical", 94, "CWE-306",
        "/api/v1/namespaces/kube-system/services", 200,
        "\"ServiceList\"", "\"kube-dns\"",
        ""
    },
    {
        "NVT-CLOUD-212",
        "Unauthenticated Grafana Loki Log Labels API (/loki/api/v1/labels)",
        "Observability Log Exposure", "High", 75, "CWE-306",
        "/loki/api/v1/labels", 200,
        "\"status\"", "\"success\"",
        ""
    },
    {
        "NVT-CLOUD-213",
        "Unauthenticated Thanos / Cortex Runtime Status (/api/v1/status/runtime"
        "info)",
        "Observability Control Exposure", "Medium", 58, "CWE-200",
        "/api/v1/status/runtimeinfo", 200,
        "\"storageRetention\"", "\"goroutineCount\"",
        ""
    },
    {
        "NVT-CLOUD-214",
        "Unauthenticated Legacy etcd v2 Keyspace API (/v2/keys)",
        "Cluster Secret Store Exposure", "Critical", 98, "CWE-306",
        "/v2/keys", 200,
        "\"action\"", "\"get\"",
        ""
    },
    {
        "NVT-CLOUD-215",
        "Unauthenticated Prometheus Alertmanager Cluster Status (/api/v2/status"
        ")",
        "Observability Control Exposure", "Medium", 58, "CWE-200",
        "/api/v2/status", 200,
        "\"cluster\"", "\"versionInfo\"",
        ""
    },
    {
        "NVT-CLOUD-216",
        "Unauthenticated Temporal Workflow Namespaces API (/api/v1/namespaces)",
        "Workflow Orchestrator Exposure", "High", 75, "CWE-306",
        "/api/v1/namespaces", 200,
        "\"namespaces\"", "\"namespaceInfo\"",
        ""
    },
    {
        "NVT-CLOUD-217",
        "Unauthenticated Apache Pulsar Clusters Admin API (/admin/v2/clusters)",
        "Streaming Control-Plane Exposure", "High", 82, "CWE-306",
        "/admin/v2/clusters", 200,
        "[", "",
        ""
    },
    {
        "NVT-CLOUD-218",
        "Unauthenticated RabbitMQ Management Overview API (/api/overview)",
        "Message Broker Exposure", "High", 82, "CWE-306",
        "/api/overview", 200,
        "\"rabbitmq_version\"", "\"erlang_version\"",
        ""
    },
    {
        "NVT-SEC-219",
        "Exposed Harbor Container Registry System Info (/api/v2.0/systeminfo)",
        "Artifact Registry Telemetry", "Medium", 53, "CWE-200",
        "/api/v2.0/systeminfo", 200,
        "\"harbor_version\"", "\"auth_mode\"",
        ""
    },
    {
        "NVT-SEC-220",
        "Exposed DefectDojo OpenAPI v3 Specification (/api/v2/oa3/schema/)",
        "Security Platform Schema Exposure", "Low", 37, "CWE-200",
        "/api/v2/oa3/schema/?format=json", 200,
        "\"DefectDojo\"", "\"paths\"",
        ""
    },
    {
        "NVT-SEC-221",
        "Exposed Forgejo Git Server Version Endpoint (/api/forgejo/v1/version)",
        "VCS Platform Telemetry", "Low", 37, "CWE-200",
        "/api/forgejo/v1/version", 200,
        "\"version\"", "",
        ""
    },
    {
        "NVT-SEC-222",
        "Unauthenticated Wazuh Manager API Info (/manager/info)",
        "SIEM Control-Plane Exposure", "High", 75, "CWE-306",
        "/manager/info", 200,
        "\"compilation_date\"", "\"ruleset_version\"",
        ""
    },
    {
        "NVT-SEC-223",
        "Unauthenticated Graylog Cluster Node Telemetry (/api/system/cluster/no"
        "de)",
        "SIEM Telemetry Exposure", "Medium", 58, "CWE-200",
        "/api/system/cluster/node", 200,
        "\"cluster_id\"", "\"node_id\"",
        ""
    },
    {
        "NVT-APP-224",
        "Unauthenticated Airbyte Workspace Health & Config (/api/v1/health)",
        "Data Pipeline Telemetry", "Low", 37, "CWE-200",
        "/api/v1/health", 200,
        "\"available\"", "",
        ""
    },
    {
        "NVT-APP-225",
        "Unauthenticated n8n Workflow Settings Telemetry (/rest/settings)",
        "Workflow Automation Telemetry", "Medium", 53, "CWE-200",
        "/rest/settings", 200,
        "\"data\"", "\"enterprise\"",
        ""
    },
    {
        "NVT-CLOUD-226",
        "Unauthenticated HAProxy Data Plane API Info (/v2/info)",
        "Load-Balancer Control Exposure", "High", 82, "CWE-306",
        "/v2/info", 200,
        "\"api\"", "\"build_date\"",
        ""
    },
    {
        "NVT-CLOUD-227",
        "Unauthenticated Kubernetes Default Namespace Secrets (/api/v1/namespac"
        "es/default/secrets)",
        "Container Secret Exposure", "Critical", 98, "CWE-306",
        "/api/v1/namespaces/default/secrets", 200,
        "\"SecretList\"", "\"items\"",
        ""
    },
    {
        "NVT-CLOUD-228",
        "Exposed Prometheus Target Metric Metadata (/api/v1/targets/metadata)",
        "Observability Telemetry Exposure", "Medium", 53, "CWE-200",
        "/api/v1/targets/metadata", 200,
        "\"status\"", "\"metric\"",
        ""
    },
    {
        "NVT-CLOUD-229",
        "Unauthenticated HashiCorp Consul ACL Policies (/v1/acl/policies)",
        "Service Mesh Control Exposure", "Critical", 91, "CWE-306",
        "/v1/acl/policies", 200,
        "\"ID\"", "\"Datacenters\"",
        ""
    },
    {
        "NVT-CLOUD-230",
        "Unauthenticated HashiCorp Nomad Cluster Jobs (/v1/jobs)",
        "Cluster Orchestrator Exposure", "High", 82, "CWE-306",
        "/v1/jobs", 200,
        "\"JobSummary\"", "\"Type\"",
        ""
    },
    {
        "NVT-DATA-231",
        "Unauthenticated OpenSearch Cluster Settings (/_cluster/settings)",
        "Database Control-Plane Exposure", "High", 82, "CWE-306",
        "/_cluster/settings", 200,
        "\"persistent\"", "\"transient\"",
        ""
    },
    {
        "NVT-DATA-232",
        "Unauthenticated Typesense Collections Inventory (/collections)",
        "Search Database Exposure", "High", 75, "CWE-306",
        "/collections", 200,
        "\"num_documents\"", "\"fields\"",
        ""
    },
    {
        "NVT-DATA-233",
        "Unauthenticated Neo4j Discovery Root Telemetry (/db/manage/server/vers"
        "ion)",
        "Graph Database Telemetry", "Medium", 53, "CWE-200",
        "/db/manage/server/version", 200,
        "\"edition\"", "\"version\"",
        ""
    },
    {
        "NVT-DEVOPS-234",
        "Exposed Jenkins Prometheus Plugin Metrics (/prometheus/)",
        "CI/CD Telemetry Exposure", "Medium", 58, "CWE-200",
        "/prometheus/", 200,
        "default_jenkins_builds_", "jenkins_version_info",
        ""
    },
    {
        "NVT-DEVOPS-235",
        "Unauthenticated SonarQube System Status Telemetry (/api/system/status)",
        "DevSecOps Platform Telemetry", "Low", 37, "CWE-200",
        "/api/system/status", 200,
        "\"status\"", "\"version\"",
        ""
    },
    {
        "NVT-DEVOPS-236",
        "Unauthenticated JFrog Artifactory System Ping & Version (/artifactory/"
        "api/system/version)",
        "Artifact Registry Telemetry", "Medium", 53, "CWE-200",
        "/artifactory/api/system/version", 200,
        "\"version\"", "\"revision\"",
        ""
    },
    {
        "NVT-NET-237",
        "Unauthenticated EMQX MQTT Broker Status API (/api/v5/status)",
        "IoT / Messaging Telemetry", "Medium", 53, "CWE-200",
        "/api/v5/status", 200,
        "node ", "is running",
        ""
    },
    {
        "NVT-NET-238",
        "Unauthenticated VerneMQ Broker Status Page (/status.json)",
        "IoT / Messaging Telemetry", "Medium", 53, "CWE-200",
        "/status.json", 200,
        "\"num_online\"", "\"total_queues\"",
        ""
    },
    {
        "NVT-APP-239",
        "Exposed Seafile Server System Info (/api2/server-info/)",
        "Enterprise File Sync Telemetry", "Low", 37, "CWE-200",
        "/api2/server-info/", 200,
        "\"version\"", "\"features\"",
        ""
    },
    {
        "NVT-APP-240",
        "Exposed OpenProject API v3 Root Configuration (/api/v3/configuration)",
        "Project Management Telemetry", "Low", 37, "CWE-200",
        "/api/v3/configuration", 200,
        "\"_type\"", "\"Configuration\"",
        ""
    },
    {
        "NVT-ZT-241",
        "Exposed Teleport Access Plane Ping Metadata (/webapi/ping)",
        "Zero-Trust Access Telemetry", "Low", 37, "CWE-200",
        "/webapi/ping", 200,
        "\"server_version\"", "\"proxy\"",
        ""
    },
    {
        "NVT-ZT-242",
        "Exposed HashiCorp Boundary Auth Methods Inventory (/v1/auth-methods)",
        "Zero-Trust Access Telemetry", "Low", 37, "CWE-200",
        "/v1/auth-methods?scope_id=global", 200,
        "\"items\"", "\"scope\"",
        ""
    },
    {
        "NVT-ZT-243",
        "Unauthenticated Headscale Control Server API Keys (/api/v1/apikey)",
        "Zero-Trust VPN Exposure", "Critical", 94, "CWE-306",
        "/api/v1/apikey", 200,
        "\"apiKeys\"", "\"prefix\"",
        ""
    },
    {
        "NVT-ZT-244",
        "Exposed OpenZiti Controller Version Telemetry (/edge/client/v1/version"
        ")",
        "Zero-Trust Network Telemetry", "Low", 37, "CWE-200",
        "/edge/client/v1/version", 200,
        "\"data\"", "\"revision\"",
        ""
    },
    {
        "NVT-DATA-245",
        "Unauthenticated Cube.js Analytics Schema Metadata (/cubejs-api/v1/meta"
        ")",
        "BI / Analytics Schema Exposure", "High", 75, "CWE-306",
        "/cubejs-api/v1/meta", 200,
        "\"cubes\"", "\"measures\"",
        ""
    },
    {
        "NVT-DATA-246",
        "Unauthenticated Dagster GraphQL Workspace Info (/server_info)",
        "Data Orchestrator Telemetry", "Medium", 58, "CWE-200",
        "/server_info", 200,
        "\"dagster_version\"", "",
        ""
    },
    {
        "NVT-DEVOPS-247",
        "Unauthenticated Rundeck System Info API (/api/44/system/info)",
        "Runbook Automation Exposure", "High", 75, "CWE-306",
        "/api/44/system/info", 200,
        "\"system\"", "\"rundeck\"",
        ""
    },
    {
        "NVT-APP-248",
        "Exposed BookStack System Instance Metadata (/api/docs.json)",
        "Knowledge Base Schema Telemetry", "Low", 37, "CWE-200",
        "/api/docs.json", 200,
        "\"BookStack\"", "\"endpoints\"",
        ""
    },
    {
        "NVT-APP-249",
        "Exposed Mastodon Instance Federation Config (/api/v2/instance)",
        "Social Platform Telemetry", "Low", 37, "CWE-200",
        "/api/v2/instance", 200,
        "\"domain\"", "\"registrations\"",
        ""
    },
    {
        "NVT-AI-250",
        "Unauthenticated vLLM Prometheus Inference Metrics (/metrics)",
        "AI / LLM Runtime Telemetry", "Medium", 58, "CWE-200",
        "/metrics", 200,
        "vllm:num_requests_running", "vllm:gpu_cache_usage_perc",
        ""
    },
    {
        "NVT-KEV-CVE-2024-10441",
        "Synology DiskStation Manager (DSM) (CVE-2024-10441) KEV Surface & Vers"
        "ion Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/diskstation-manager-dsm/version", 200,
        "\"diskstation-manager-dsm\"", "\"synology\"",
        "tech/stack=diskstation\\-manager\\-dsm"
    },
    {
        "NVT-KEV-CVE-2026-40217",
        "BerriAI LiteLLM (CVE-2026-40217) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/litellm/version", 200,
        "\"litellm\"", "\"berriai\"",
        "tech/stack=litellm"
    },
    {
        "NVT-KEV-CVE-2026-90817",
        "Vanderbilt University Research Electronic Data Capture (REDCap) (CVE-2"
        "026-90817) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/research-electronic-data-capture-red/version", 200,
        "\"research-electronic-data-capture-red\"", "\"vanderbilt-university\"",
        "tech/stack=research\\-electronic\\-data\\-capture\\-red"
    },
    {
        "NVT-KEV-CVE-2026-90436",
        "Apache Axis (CVE-2026-90436) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/axis/version", 200,
        "\"axis\"", "\"apache\"",
        "tech/stack=axis"
    },
    {
        "NVT-KEV-CVE-2026-115731",
        "Perforce Puppet Enterprise (CVE-2026-115731) KEV Surface & Version Met"
        "adata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-502",
        "/api/v1/puppet-enterprise/version", 200,
        "\"puppet-enterprise\"", "\"perforce\"",
        "tech/stack=puppet\\-enterprise"
    },
    {
        "NVT-KEV-CVE-2026-114713",
        "UnrealIRCd UnrealIRCd (CVE-2026-114713) KEV Surface & Version Metadata"
        " Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/unrealircd/version", 200,
        "\"unrealircd\"", "\"unrealircd\"",
        "tech/stack=unrealircd"
    },
    {
        "NVT-KEV-CVE-2026-123039",
        "Check Point Multiple Products (CVE-2026-123039) KEV Surface & Version "
        "Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"check-point\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2026-124194",
        "Microsoft Office (CVE-2026-124194) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/office/version", 200,
        "\"office\"", "\"microsoft\"",
        "tech/stack=office"
    },
    {
        "NVT-KEV-CVE-2026-111793",
        "Openwave Messaging Limited Webtop Media Transcoder (CVE-2026-111793) K"
        "EV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/webtop-media-transcoder/version", 200,
        "\"webtop-media-transcoder\"", "\"openwave-messaging-limited\"",
        "tech/stack=webtop\\-media\\-transcoder"
    },
    {
        "NVT-KEV-CVE-2026-20320",
        "Cisco BroadWorks (CVE-2026-20320) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/broadworks/version", 200,
        "\"broadworks\"", "\"cisco\"",
        "tech/stack=broadworks"
    },
    {
        "NVT-KEV-CVE-2026-111560",
        "Barracuda Networks Multiple Products (CVE-2026-111560) KEV Surface & V"
        "ersion Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"barracuda-networks\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2026-116606",
        "Barracuda Networks Barracuda Email Security Gateway (ESG) (CVE-2026-11"
        "6606) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/barracuda-email-security-gateway-esg/version", 200,
        "\"barracuda-email-security-gateway-esg\"", "\"barracuda-networks\"",
        "tech/stack=barracuda\\-email\\-security\\-gateway\\-esg"
    },
    {
        "NVT-KEV-CVE-2026-125350",
        "Google Chromium (CVE-2026-125350) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/chromium/version", 200,
        "\"chromium\"", "\"google\"",
        "tech/stack=chromium"
    },
    {
        "NVT-KEV-CVE-2026-102895",
        "GPUStack GPUStack (CVE-2026-102895) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/gpustack/version", 200,
        "\"gpustack\"", "\"gpustack\"",
        "tech/stack=gpustack"
    },
    {
        "NVT-KEV-CVE-2026-123158",
        "OpenBSD OpenSSH (CVE-2026-123158) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/openssh/version", 200,
        "\"openssh\"", "\"openbsd\"",
        "tech/stack=openssh"
    },
    {
        "NVT-KEV-CVE-2026-116779",
        "SignalWire FreeSwitch (CVE-2026-116779) KEV Surface & Version Metadata"
        " Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/freeswitch/version", 200,
        "\"freeswitch\"", "\"signalwire\"",
        "tech/stack=freeswitch"
    },
    {
        "NVT-KEV-CVE-2026-123218",
        "IBM Aspera Faspex (CVE-2026-123218) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/aspera-faspex/version", 200,
        "\"aspera-faspex\"", "\"ibm\"",
        "tech/stack=aspera\\-faspex"
    },
    {
        "NVT-KEV-CVE-2026-19868",
        "SonicWall SonicOS SSLVPN (CVE-2026-19868) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/sonicos-sslvpn/version", 200,
        "\"sonicos-sslvpn\"", "\"sonicwall\"",
        "tech/stack=sonicos\\-sslvpn"
    },
    {
        "NVT-KEV-CVE-2024-27834",
        "Apple Multiple Products (CVE-2024-27834) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"apple\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2026-119977",
        "WordPress WordPress Core (CVE-2026-119977) KEV Surface & Version Metad"
        "ata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/wordpress-core/version", 200,
        "\"wordpress-core\"", "\"wordpress\"",
        "tech/stack=wordpress\\-core"
    },
    {
        "NVT-KEV-CVE-2026-118527",
        "Ivanti Connect Secure (CVE-2026-118527) KEV Surface & Version Metadata"
        " Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/connect-secure/version", 200,
        "\"connect-secure\"", "\"ivanti\"",
        "tech/stack=connect\\-secure"
    },
    {
        "NVT-KEV-CVE-2026-111357",
        "Ivanti Connect Secure (CVE-2026-111357) KEV Surface & Version Metadata"
        " Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-306",
        "/api/v1/connect-secure/version", 200,
        "\"connect-secure\"", "\"ivanti\"",
        "tech/stack=connect\\-secure"
    },
    {
        "NVT-KEV-CVE-2026-97229",
        "GitLab Community Edition and Enterprise Edition (CVE-2026-97229) KEV S"
        "urface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/community-edition-and-enterprise-edi/version", 200,
        "\"community-edition-and-enterprise-edi\"", "\"gitlab\"",
        "tech/stack=community\\-edition\\-and\\-enterprise\\-edi"
    },
    {
        "NVT-KEV-CVE-2026-76418",
        "Cisco Secure Firewall ASA Software and Cisco Secure FTD Software (CVE-"
        "2026-76418) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/secure-firewall-asa-software-and-cis/version", 200,
        "\"secure-firewall-asa-software-and-cis\"", "\"cisco\"",
        "tech/stack=secure\\-firewall\\-asa\\-software\\-and\\-cis"
    },
    {
        "NVT-KEV-CVE-2026-41709",
        "Broadcom VMware ESX (CVE-2026-41709) KEV Surface & Version Metadata Ex"
        "posure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/vmware-esx/version", 200,
        "\"vmware-esx\"", "\"broadcom\"",
        "tech/stack=vmware\\-esx"
    },
    {
        "NVT-KEV-CVE-2026-46300",
        "Linux Kernel (CVE-2026-46300) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/kernel/version", 200,
        "\"kernel\"", "\"linux\"",
        "tech/stack=kernel"
    },
    {
        "NVT-KEV-CVE-2026-48356",
        "Adobe Commerce and Magento (CVE-2026-48356) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/commerce-and-magento/version", 200,
        "\"commerce-and-magento\"", "\"adobe\"",
        "tech/stack=commerce\\-and\\-magento"
    },
    {
        "NVT-KEV-CVE-2026-111497",
        "Google Brotli (CVE-2026-111497) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/brotli/version", 200,
        "\"brotli\"", "\"google\"",
        "tech/stack=brotli"
    },
    {
        "NVT-KEV-CVE-2026-109618",
        "PHP Group PHP (CVE-2026-109618) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/php/version", 200,
        "\"php\"", "\"php-group\"",
        "tech/stack=php"
    },
    {
        "NVT-KEV-CVE-2026-109619",
        "PHP Group PHP (CVE-2026-109619) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/php/version", 200,
        "\"php\"", "\"php-group\"",
        "tech/stack=php"
    },
    {
        "NVT-KEV-CVE-2026-114625",
        "Arista VeloCloud Orchestrator (CVE-2026-114625) KEV Surface & Version "
        "Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-89",
        "/api/v1/velocloud-orchestrator/version", 200,
        "\"velocloud-orchestrator\"", "\"arista\"",
        "tech/stack=velocloud\\-orchestrator"
    },
    {
        "NVT-KEV-CVE-2026-110447",
        "Collabora Collabora Online – Built-in CODE Server (CVE-2026-110447) KE"
        "V Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/collabora-online-built-in-code-serve/version", 200,
        "\"collabora-online-built-in-code-serve\"", "\"collabora\"",
        "tech/stack=collabora\\-online\\-built\\-in\\-code\\-serve"
    },
    {
        "NVT-KEV-CVE-2026-106931",
        "EG Secure Solutions SiteGuard Server Edition (CVE-2026-106931) KEV Sur"
        "face & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/siteguard-server-edition/version", 200,
        "\"siteguard-server-edition\"", "\"eg-secure-solutions\"",
        "tech/stack=siteguard\\-server\\-edition"
    },
    {
        "NVT-KEV-CVE-2026-96656",
        "Plex Media Server (CVE-2026-96656) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/media-server/version", 200,
        "\"media-server\"", "\"plex\"",
        "tech/stack=media\\-server"
    },
    {
        "NVT-KEV-CVE-2026-96655",
        "Plex Media Server (CVE-2026-96655) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-918",
        "/api/v1/media-server/version", 200,
        "\"media-server\"", "\"plex\"",
        "tech/stack=media\\-server"
    },
    {
        "NVT-KEV-CVE-2026-96654",
        "Plex Media Server (CVE-2026-96654) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/media-server/version", 200,
        "\"media-server\"", "\"plex\"",
        "tech/stack=media\\-server"
    },
    {
        "NVT-KEV-CVE-2026-96652",
        "Plex Media Server (CVE-2026-96652) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-918",
        "/api/v1/media-server/version", 200,
        "\"media-server\"", "\"plex\"",
        "tech/stack=media\\-server"
    },
    {
        "NVT-KEV-CVE-2026-110936",
        "Siemens Software Center (CVE-2026-110936) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/software-center/version", 200,
        "\"software-center\"", "\"siemens\"",
        "tech/stack=software\\-center"
    },
    {
        "NVT-KEV-CVE-2026-102764",
        "BeyondTrust Remote Support (CVE-2026-102764) KEV Surface & Version Met"
        "adata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/remote-support/version", 200,
        "\"remote-support\"", "\"beyondtrust\"",
        "tech/stack=remote\\-support"
    },
    {
        "NVT-KEV-CVE-2025-61624",
        "Fortinet Multiple Products (CVE-2025-61624) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"fortinet\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2026-21589",
        "Atlassian Multiple Products (CVE-2026-21589) KEV Surface & Version Met"
        "adata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"atlassian\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2026-105134",
        "Ahsay AhsayCBS (CVE-2026-105134) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/ahsaycbs/version", 200,
        "\"ahsaycbs\"", "\"ahsay\"",
        "tech/stack=ahsaycbs"
    },
    {
        "NVT-KEV-CVE-2026-76519",
        "Cisco Secure Email Gateway (CVE-2026-76519) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/secure-email-gateway/version", 200,
        "\"secure-email-gateway\"", "\"cisco\"",
        "tech/stack=secure\\-email\\-gateway"
    },
    {
        "NVT-KEV-CVE-2026-105133",
        "Ahsay AhsayCBS (CVE-2026-105133) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/ahsaycbs/version", 200,
        "\"ahsaycbs\"", "\"ahsay\"",
        "tech/stack=ahsaycbs"
    },
    {
        "NVT-KEV-CVE-2026-0322",
        "Palo Alto Networks PAN-OS (CVE-2026-0322) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/pan-os/version", 200,
        "\"pan-os\"", "\"palo-alto-networks\"",
        "tech/stack=pan\\-os"
    },
    {
        "NVT-KEV-CVE-2026-104935",
        "Ivanti Connect Secure (CVE-2026-104935) KEV Surface & Version Metadata"
        " Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/connect-secure/version", 200,
        "\"connect-secure\"", "\"ivanti\"",
        "tech/stack=connect\\-secure"
    },
    {
        "NVT-KEV-CVE-2026-96951",
        "Microsoft Windows (CVE-2026-96951) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2015-5477",
        "ISC BIND (CVE-2015-5477) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/bind/version", 200,
        "\"bind\"", "\"isc\"",
        "tech/stack=bind"
    },
    {
        "NVT-KEV-CVE-2016-3081",
        "Apache Struts (CVE-2016-3081) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/struts/version", 200,
        "\"struts\"", "\"apache\"",
        "tech/stack=struts"
    },
    {
        "NVT-KEV-CVE-2023-22894",
        "Strapi Strapi (CVE-2023-22894) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/strapi/version", 200,
        "\"strapi\"", "\"strapi\"",
        "tech/stack=strapi"
    },
    {
        "NVT-KEV-CVE-2021-3199",
        "ONLYOFFICE Docs (CVE-2021-3199) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/docs/version", 200,
        "\"docs\"", "\"onlyoffice\"",
        "tech/stack=docs"
    },
    {
        "NVT-KEV-CVE-2015-3306",
        "ProFTPD ProFTPD (CVE-2015-3306) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/proftpd/version", 200,
        "\"proftpd\"", "\"proftpd\"",
        "tech/stack=proftpd"
    },
    {
        "NVT-KEV-CVE-2026-88779",
        "Citrix NetScaler (CVE-2026-88779) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/netscaler/version", 200,
        "\"netscaler\"", "\"citrix\"",
        "tech/stack=netscaler"
    },
    {
        "NVT-KEV-CVE-2026-102490",
        "Zammad GmbH Zammad (CVE-2026-102490) KEV Surface & Version Metadata Ex"
        "posure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/zammad/version", 200,
        "\"zammad\"", "\"zammad-gmbh\"",
        "tech/stack=zammad"
    },
    {
        "NVT-KEV-CVE-2026-102489",
        "Zammad GmbH Zammad (CVE-2026-102489) KEV Surface & Version Metadata Ex"
        "posure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/zammad/version", 200,
        "\"zammad\"", "\"zammad-gmbh\"",
        "tech/stack=zammad"
    },
    {
        "NVT-KEV-CVE-2026-104286",
        "Fortinet FortiMail (CVE-2026-104286) KEV Surface & Version Metadata Ex"
        "posure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/fortimail/version", 200,
        "\"fortimail\"", "\"fortinet\"",
        "tech/stack=fortimail"
    },
    {
        "NVT-KEV-CVE-2026-76504",
        "Cisco Catalyst SD-WAN Manager (CVE-2026-76504) KEV Surface & Version M"
        "etadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/catalyst-sd-wan-manager/version", 200,
        "\"catalyst-sd-wan-manager\"", "\"cisco\"",
        "tech/stack=catalyst\\-sd\\-wan\\-manager"
    },
    {
        "NVT-KEV-CVE-2026-86950",
        "Apple Multiple Products (CVE-2026-86950) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"apple\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2026-88772",
        "Citrix NetScaler (CVE-2026-88772) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/netscaler/version", 200,
        "\"netscaler\"", "\"citrix\"",
        "tech/stack=netscaler"
    },
    {
        "NVT-KEV-CVE-2026-88771",
        "Citrix NetScaler (CVE-2026-88771) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/netscaler/version", 200,
        "\"netscaler\"", "\"citrix\"",
        "tech/stack=netscaler"
    },
    {
        "NVT-KEV-CVE-2026-67279",
        "MikroTik RouterOS (CVE-2026-67279) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/routeros/version", 200,
        "\"routeros\"", "\"mikrotik\"",
        "tech/stack=routeros"
    },
    {
        "NVT-KEV-CVE-2026-65660",
        "Microsoft SharePoint (CVE-2026-65660) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/sharepoint/version", 200,
        "\"sharepoint\"", "\"microsoft\"",
        "tech/stack=sharepoint"
    },
    {
        "NVT-KEV-CVE-2026-87902",
        "WordPress Core (CVE-2026-87902) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/core/version", 200,
        "\"core\"", "\"wordpress\"",
        "tech/stack=core"
    },
    {
        "NVT-KEV-CVE-2026-5430",
        "WSO2 Multiple Products (CVE-2026-5430) KEV Surface & Version Metadata "
        "Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"wso2\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2026-71362",
        "Adobe Commerce and Magento (CVE-2026-71362) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/commerce-and-magento/version", 200,
        "\"commerce-and-magento\"", "\"adobe\"",
        "tech/stack=commerce\\-and\\-magento"
    },
    {
        "NVT-KEV-CVE-2026-93952",
        "Arista VeloCloud Orchestrator (CVE-2026-93952) KEV Surface & Version M"
        "etadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/velocloud-orchestrator/version", 200,
        "\"velocloud-orchestrator\"", "\"arista\"",
        "tech/stack=velocloud\\-orchestrator"
    },
    {
        "NVT-KEV-CVE-2026-94127",
        "F5 BIG-IP APM (CVE-2026-94127) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/big-ip-apm/version", 200,
        "\"big-ip-apm\"", "\"prod-f5\"",
        "tech/stack=big\\-ip\\-apm"
    },
    {
        "NVT-KEV-CVE-2026-93616",
        "Check Point Multiple Products (CVE-2026-93616) KEV Surface & Version M"
        "etadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"check-point\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2026-85102",
        "Check Point Multiple Products (CVE-2026-85102) KEV Surface & Version M"
        "etadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"check-point\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2026-7273",
        "Zyxel GS1900 Series Switches (CVE-2026-7273) KEV Surface & Version Met"
        "adata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/gs1900-series-switches/version", 200,
        "\"gs1900-series-switches\"", "\"zyxel\"",
        "tech/stack=gs1900\\-series\\-switches"
    },
    {
        "NVT-KEV-CVE-2025-39964",
        "Linux Kernel (CVE-2025-39964) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/kernel/version", 200,
        "\"kernel\"", "\"linux\"",
        "tech/stack=kernel"
    },
    {
        "NVT-KEV-CVE-2026-53266",
        "Linux Kernel (CVE-2026-53266) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/kernel/version", 200,
        "\"kernel\"", "\"linux\"",
        "tech/stack=kernel"
    },
    {
        "NVT-KEV-CVE-2025-39682",
        "Linux Kernel (CVE-2025-39682) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/kernel/version", 200,
        "\"kernel\"", "\"linux\"",
        "tech/stack=kernel"
    },
    {
        "NVT-KEV-CVE-2026-58704",
        "Google Pixel (CVE-2026-58704) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/pixel/version", 200,
        "\"pixel\"", "\"google\"",
        "tech/stack=pixel"
    },
    {
        "NVT-KEV-CVE-2026-76460",
        "Cisco Identity Services Engine (CVE-2026-76460) KEV Surface & Version "
        "Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/identity-services-engine/version", 200,
        "\"identity-services-engine\"", "\"cisco\"",
        "tech/stack=identity\\-services\\-engine"
    },
    {
        "NVT-KEV-CVE-2026-87886",
        "Acronis Backup (CVE-2026-87886) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/backup/version", 200,
        "\"backup\"", "\"acronis\"",
        "tech/stack=backup"
    },
    {
        "NVT-KEV-CVE-2026-76461",
        "Cisco Secure Email Gateway (CVE-2026-76461) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-89",
        "/api/v1/secure-email-gateway/version", 200,
        "\"secure-email-gateway\"", "\"cisco\"",
        "tech/stack=secure\\-email\\-gateway"
    },
    {
        "NVT-KEV-CVE-2026-84869",
        "ConnectWise ScreenConnect (CVE-2026-84869) KEV Surface & Version Metad"
        "ata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/screenconnect/version", 200,
        "\"screenconnect\"", "\"connectwise\"",
        "tech/stack=screenconnect"
    },
    {
        "NVT-KEV-CVE-2026-42016",
        "JFrog Artifactory (CVE-2026-42016) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/artifactory/version", 200,
        "\"artifactory\"", "\"jfrog\"",
        "tech/stack=artifactory"
    },
    {
        "NVT-KEV-CVE-2026-42018",
        "JFrog Artifactory (CVE-2026-42018) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/artifactory/version", 200,
        "\"artifactory\"", "\"jfrog\"",
        "tech/stack=artifactory"
    },
    {
        "NVT-KEV-CVE-2026-85706",
        "GitLab Community Edition and Enterprise Edition (CVE-2026-85706) KEV S"
        "urface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/community-edition-and-enterprise-edi/version", 200,
        "\"community-edition-and-enterprise-edi\"", "\"gitlab\"",
        "tech/stack=community\\-edition\\-and\\-enterprise\\-edi"
    },
    {
        "NVT-KEV-CVE-2026-86060",
        "MikroTik RouterOS (CVE-2026-86060) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/routeros/version", 200,
        "\"routeros\"", "\"mikrotik\"",
        "tech/stack=routeros"
    },
    {
        "NVT-KEV-CVE-2026-67277",
        "MikroTik RouterOS (CVE-2026-67277) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-306",
        "/api/v1/routeros/version", 200,
        "\"routeros\"", "\"mikrotik\"",
        "tech/stack=routeros"
    },
    {
        "NVT-KEV-CVE-2026-19490",
        "Citrix NetScaler (CVE-2026-19490) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/netscaler/version", 200,
        "\"netscaler\"", "\"citrix\"",
        "tech/stack=netscaler"
    },
    {
        "NVT-KEV-CVE-2025-25249",
        "Fortinet Multiple Products (CVE-2025-25249) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"fortinet\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2026-87491",
        "Google Chromium V8 (CVE-2026-87491) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/chromium-v8/version", 200,
        "\"chromium-v8\"", "\"google\"",
        "tech/stack=chromium\\-v8"
    },
    {
        "NVT-KEV-CVE-2026-20079",
        "Cisco Secure Firewall Management Center (FMC) and Security Cloud Contr"
        "ol (SCC) Firewall Management (CVE-2026-20079) KEV Surface & Version Me",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/secure-firewall-management-center-fm/version", 200,
        "\"secure-firewall-management-center-fm\"", "\"cisco\"",
        "tech/stack=secure\\-firewall\\-management\\-center\\-fm"
    },
    {
        "NVT-KEV-CVE-2026-75650",
        "Adobe Commerce and Magento (CVE-2026-75650) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/commerce-and-magento/version", 200,
        "\"commerce-and-magento\"", "\"adobe\"",
        "tech/stack=commerce\\-and\\-magento"
    },
    {
        "NVT-KEV-CVE-2026-81963",
        "Microsoft Windows (CVE-2026-81963) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2026-86218",
        "N-able N-central (CVE-2026-86218) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/n-central/version", 200,
        "\"n-central\"", "\"n-able\"",
        "tech/stack=n\\-central"
    },
    {
        "NVT-KEV-CVE-2026-85880",
        "Microsoft Windows (CVE-2026-85880) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2026-85046",
        "Google Chromium V8 (CVE-2026-85046) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/chromium-v8/version", 200,
        "\"chromium-v8\"", "\"google\"",
        "tech/stack=chromium\\-v8"
    },
    {
        "NVT-KEV-CVE-2026-59822",
        "BerriAI LiteLLM (CVE-2026-59822) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/litellm/version", 200,
        "\"litellm\"", "\"berriai\"",
        "tech/stack=litellm"
    },
    {
        "NVT-KEV-CVE-2026-48710",
        "Kludex Starlette (CVE-2026-48710) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/starlette/version", 200,
        "\"starlette\"", "\"kludex\"",
        "tech/stack=starlette"
    },
    {
        "NVT-KEV-CVE-2026-49869",
        "Kestra Kestra OSS (CVE-2026-49869) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/kestra-oss/version", 200,
        "\"kestra-oss\"", "\"kestra\"",
        "tech/stack=kestra\\-oss"
    },
    {
        "NVT-KEV-CVE-2026-82329",
        "JFrog Artifactory (CVE-2026-82329) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/artifactory/version", 200,
        "\"artifactory\"", "\"jfrog\"",
        "tech/stack=artifactory"
    },
    {
        "NVT-KEV-CVE-2026-9586",
        "Sangoma Switchvox (CVE-2026-9586) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-89",
        "/api/v1/switchvox/version", 200,
        "\"switchvox\"", "\"sangoma\"",
        "tech/stack=switchvox"
    },
    {
        "NVT-KEV-CVE-2026-83548",
        "SonicWall SMA1000 Appliances (CVE-2026-83548) KEV Surface & Version Me"
        "tadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-918",
        "/api/v1/sma1000-appliances/version", 200,
        "\"sma1000-appliances\"", "\"sonicwall\"",
        "tech/stack=sma1000\\-appliances"
    },
    {
        "NVT-KEV-CVE-2026-83549",
        "SonicWall SMA1000 Appliances (CVE-2026-83549) KEV Surface & Version Me"
        "tadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/sma1000-appliances/version", 200,
        "\"sma1000-appliances\"", "\"sonicwall\"",
        "tech/stack=sma1000\\-appliances"
    },
    {
        "NVT-KEV-CVE-2026-82078",
        "PaperCut NG/MF (CVE-2026-82078) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/ng-mf/version", 200,
        "\"ng-mf\"", "\"papercut\"",
        "tech/stack=ng\\-mf"
    },
    {
        "NVT-KEV-CVE-2026-81578",
        "PaperCut NG/MF (CVE-2026-81578) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-306",
        "/api/v1/ng-mf/version", 200,
        "\"ng-mf\"", "\"papercut\"",
        "tech/stack=ng\\-mf"
    },
    {
        "NVT-KEV-CVE-2023-49105",
        "ownCloud ownCloud (CVE-2023-49105) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/owncloud/version", 200,
        "\"owncloud\"", "\"owncloud\"",
        "tech/stack=owncloud"
    },
    {
        "NVT-KEV-CVE-2026-53362",
        "Linux Kernel (CVE-2026-53362) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/kernel/version", 200,
        "\"kernel\"", "\"linux\"",
        "tech/stack=kernel"
    },
    {
        "NVT-KEV-CVE-2026-66384",
        "JFrog Artifactory (CVE-2026-66384) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/artifactory/version", 200,
        "\"artifactory\"", "\"jfrog\"",
        "tech/stack=artifactory"
    },
    {
        "NVT-KEV-CVE-2021-23758",
        "Ajax.NET Professional Ajax.NET Professional (CVE-2021-23758) KEV Surfa"
        "ce & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-502",
        "/api/v1/ajax-net-professional/version", 200,
        "\"ajax-net-professional\"", "\"ajax-net-professional\"",
        "tech/stack=ajax\\-net\\-professional"
    },
    {
        "NVT-KEV-CVE-2015-3246",
        "Red Hat Libuser (CVE-2015-3246) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/libuser/version", 200,
        "\"libuser\"", "\"red-hat\"",
        "tech/stack=libuser"
    },
    {
        "NVT-KEV-CVE-2015-5287",
        "Red Hat Automatic Bug Reporting Tool (CVE-2015-5287) KEV Surface & Ver"
        "sion Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/automatic-bug-reporting-tool/version", 200,
        "\"automatic-bug-reporting-tool\"", "\"red-hat\"",
        "tech/stack=automatic\\-bug\\-reporting\\-tool"
    },
    {
        "NVT-KEV-CVE-2022-0995",
        "Linux Kernel (CVE-2022-0995) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/kernel/version", 200,
        "\"kernel\"", "\"linux\"",
        "tech/stack=kernel"
    },
    {
        "NVT-KEV-CVE-2026-8452",
        "Citrix NetScaler ADC and NetScaler Gateway (CVE-2026-8452) KEV Surface"
        " & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/netscaler-adc-and-netscaler-gateway/version", 200,
        "\"netscaler-adc-and-netscaler-gateway\"", "\"citrix\"",
        "tech/stack=netscaler\\-adc\\-and\\-netscaler\\-gateway"
    },
    {
        "NVT-KEV-CVE-2019-1068",
        "Microsoft SQL Server (CVE-2019-1068) KEV Surface & Version Metadata Ex"
        "posure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/sql-server/version", 200,
        "\"sql-server\"", "\"microsoft\"",
        "tech/stack=sql\\-server"
    },
    {
        "NVT-KEV-CVE-2026-60004",
        "Gitea Gitea (CVE-2026-60004) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/gitea/version", 200,
        "\"gitea\"", "\"gitea\"",
        "tech/stack=gitea"
    },
    {
        "NVT-KEV-CVE-2026-21962",
        "Oracle HTTP Server and Oracle Weblogic Server Proxy Plug-in (CVE-2026-"
        "21962) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/http-server-and-oracle-weblogic-serv/version", 200,
        "\"http-server-and-oracle-weblogic-serv\"", "\"oracle\"",
        "tech/stack=http\\-server\\-and\\-oracle\\-weblogic\\-serv"
    },
    {
        "NVT-KEV-CVE-2026-73570",
        "Synacor Zimbra Collaboration Suite (ZCS) (CVE-2026-73570) KEV Surface "
        "& Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/zimbra-collaboration-suite-zcs/version", 200,
        "\"zimbra-collaboration-suite-zcs\"", "\"synacor\"",
        "tech/stack=zimbra\\-collaboration\\-suite\\-zcs"
    },
    {
        "NVT-KEV-CVE-2026-72530",
        "TrueConf Server (CVE-2026-72530) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/server/version", 200,
        "\"server\"", "\"trueconf\"",
        "tech/stack=server"
    },
    {
        "NVT-KEV-CVE-2026-72529",
        "TrueConf Server (CVE-2026-72529) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-306",
        "/api/v1/server/version", 200,
        "\"server\"", "\"trueconf\"",
        "tech/stack=server"
    },
    {
        "NVT-KEV-CVE-2026-64849",
        "MLflow MLflow (CVE-2026-64849) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-918",
        "/api/v1/mlflow/version", 200,
        "\"mlflow\"", "\"mlflow\"",
        "tech/stack=mlflow"
    },
    {
        "NVT-KEV-CVE-2026-33824",
        "Microsoft Internet Key Exchange (IKE) Service Extensions (CVE-2026-338"
        "24) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/internet-key-exchange-ike-service-ex/version", 200,
        "\"internet-key-exchange-ike-service-ex\"", "\"microsoft\"",
        "tech/stack=internet\\-key\\-exchange\\-ike\\-service\\-ex"
    },
    {
        "NVT-KEV-CVE-2026-59310",
        "Broadcom VMware vCenter (CVE-2026-59310) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-22",
        "/api/v1/vmware-vcenter/version", 200,
        "\"vmware-vcenter\"", "\"broadcom\"",
        "tech/stack=vmware\\-vcenter"
    },
    {
        "NVT-KEV-CVE-2026-55040",
        "Microsoft SharePoint (CVE-2026-55040) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/sharepoint/version", 200,
        "\"sharepoint\"", "\"microsoft\"",
        "tech/stack=sharepoint"
    },
    {
        "NVT-KEV-CVE-2026-65400",
        "Apple macOS (CVE-2026-65400) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/macos/version", 200,
        "\"macos\"", "\"apple\"",
        "tech/stack=macos"
    },
    {
        "NVT-KEV-CVE-2025-62593",
        "Ray-Project Ray (CVE-2025-62593) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/ray/version", 200,
        "\"ray\"", "\"ray-project\"",
        "tech/stack=ray"
    },
    {
        "NVT-KEV-CVE-2026-20349",
        "Cisco Secure Firewall Adaptive Security Appliance (ASA) and Secure Fir"
        "ewall Threat Defense (FTD) (CVE-2026-20349) KEV Surface & Version Meta",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/secure-firewall-adaptive-security-ap/version", 200,
        "\"secure-firewall-adaptive-security-ap\"", "\"cisco\"",
        "tech/stack=secure\\-firewall\\-adaptive\\-security\\-ap"
    },
    {
        "NVT-KEV-CVE-2026-68820",
        "Microsoft Windows Ancillary Function Driver for WinSock (CVE-2026-6882"
        "0) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows-ancillary-function-driver-fo/version", 200,
        "\"windows-ancillary-function-driver-fo\"", "\"microsoft\"",
        "tech/stack=windows\\-ancillary\\-function\\-driver\\-fo"
    },
    {
        "NVT-KEV-CVE-2026-72898",
        "Metabase Metabase (CVE-2026-72898) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-89",
        "/api/v1/metabase/version", 200,
        "\"metabase\"", "\"metabase\"",
        "tech/stack=metabase"
    },
    {
        "NVT-KEV-CVE-2026-8037",
        "Progress LoadMaster (CVE-2026-8037) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/loadmaster/version", 200,
        "\"loadmaster\"", "\"progress\"",
        "tech/stack=loadmaster"
    },
    {
        "NVT-KEV-CVE-2026-63077",
        "JetBrains TeamCity (CVE-2026-63077) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-502",
        "/api/v1/teamcity/version", 200,
        "\"teamcity\"", "\"jetbrains\"",
        "tech/stack=teamcity"
    },
    {
        "NVT-KEV-CVE-2026-18556",
        "N-able N-central (CVE-2026-18556) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/n-central/version", 200,
        "\"n-central\"", "\"n-able\"",
        "tech/stack=n\\-central"
    },
    {
        "NVT-KEV-CVE-2026-34486",
        "Apache Tomcat (CVE-2026-34486) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/tomcat/version", 200,
        "\"tomcat\"", "\"apache\"",
        "tech/stack=tomcat"
    },
    {
        "NVT-KEV-CVE-2026-9198",
        "IBM Langflow (CVE-2026-9198) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/langflow/version", 200,
        "\"langflow\"", "\"ibm\"",
        "tech/stack=langflow"
    },
    {
        "NVT-KEV-CVE-2026-18577",
        "N-able N-central (CVE-2026-18577) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/n-central/version", 200,
        "\"n-central\"", "\"n-able\"",
        "tech/stack=n\\-central"
    },
    {
        "NVT-KEV-CVE-2026-20316",
        "Cisco Secure Firewall Management Center (FMC) (CVE-2026-20316) KEV Sur"
        "face & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/secure-firewall-management-center-fm/version", 200,
        "\"secure-firewall-management-center-fm\"", "\"cisco\"",
        "tech/stack=secure\\-firewall\\-management\\-center\\-fm"
    },
    {
        "NVT-KEV-CVE-2025-68686",
        "Fortinet FortiOS (CVE-2025-68686) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-200",
        "/api/v1/fortios/version", 200,
        "\"fortios\"", "\"fortinet\"",
        "tech/stack=fortios"
    },
    {
        "NVT-KEV-CVE-2026-16812",
        "Arista VeloCloud Orchestrator (CVE-2026-16812) KEV Surface & Version M"
        "etadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/velocloud-orchestrator/version", 200,
        "\"velocloud-orchestrator\"", "\"arista\"",
        "tech/stack=velocloud\\-orchestrator"
    },
    {
        "NVT-KEV-CVE-2026-16232",
        "Check Point SmartConsole (CVE-2026-16232) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/smartconsole/version", 200,
        "\"smartconsole\"", "\"check-point\"",
        "tech/stack=smartconsole"
    },
    {
        "NVT-KEV-CVE-2026-50522",
        "Microsoft SharePoint (CVE-2026-50522) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-502",
        "/api/v1/sharepoint/version", 200,
        "\"sharepoint\"", "\"microsoft\"",
        "tech/stack=sharepoint"
    },
    {
        "NVT-KEV-CVE-2026-60137",
        "WordPress Core (CVE-2026-60137) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-89",
        "/api/v1/core/version", 200,
        "\"core\"", "\"wordpress\"",
        "tech/stack=core"
    },
    {
        "NVT-KEV-CVE-2026-63030",
        "WordPress Core (CVE-2026-63030) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/core/version", 200,
        "\"core\"", "\"wordpress\"",
        "tech/stack=core"
    },
    {
        "NVT-KEV-CVE-2026-0770",
        "Langflow Langflow (CVE-2026-0770) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/langflow/version", 200,
        "\"langflow\"", "\"langflow\"",
        "tech/stack=langflow"
    },
    {
        "NVT-KEV-CVE-2021-27137",
        "DD-WRT DD-WRT (CVE-2021-27137) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/dd-wrt/version", 200,
        "\"dd-wrt\"", "\"dd-wrt\"",
        "tech/stack=dd\\-wrt"
    },
    {
        "NVT-KEV-CVE-2026-58644",
        "Microsoft SharePoint (CVE-2026-58644) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-502",
        "/api/v1/sharepoint/version", 200,
        "\"sharepoint\"", "\"microsoft\"",
        "tech/stack=sharepoint"
    },
    {
        "NVT-KEV-CVE-2026-25089",
        "Fortinet FortiSandbox (CVE-2026-25089) KEV Surface & Version Metadata "
        "Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/fortisandbox/version", 200,
        "\"fortisandbox\"", "\"fortinet\"",
        "tech/stack=fortisandbox"
    },
    {
        "NVT-KEV-CVE-2026-39808",
        "Fortinet FortiSandbox (CVE-2026-39808) KEV Surface & Version Metadata "
        "Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/fortisandbox/version", 200,
        "\"fortisandbox\"", "\"fortinet\"",
        "tech/stack=fortisandbox"
    },
    {
        "NVT-KEV-CVE-2026-46817",
        "Oracle E-Business Suite (CVE-2026-46817) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/e-business-suite/version", 200,
        "\"e-business-suite\"", "\"oracle\"",
        "tech/stack=e\\-business\\-suite"
    },
    {
        "NVT-KEV-CVE-2023-4346",
        "KNX Association KNX Protocol Connection Authorization Option 1 (CVE-20"
        "23-4346) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/knx-protocol-connection-authorizatio/version", 200,
        "\"knx-protocol-connection-authorizatio\"", "\"knx-association\"",
        "tech/stack=knx\\-protocol\\-connection\\-authorizatio"
    },
    {
        "NVT-KEV-CVE-2026-56155",
        "Microsoft Active Directory Federation Services (CVE-2026-56155) KEV Su"
        "rface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/active-directory-federation-services/version", 200,
        "\"active-directory-federation-services\"", "\"microsoft\"",
        "tech/stack=active\\-directory\\-federation\\-services"
    },
    {
        "NVT-KEV-CVE-2026-56164",
        "Microsoft SharePoint Server (CVE-2026-56164) KEV Surface & Version Met"
        "adata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-306",
        "/api/v1/sharepoint-server/version", 200,
        "\"sharepoint-server\"", "\"microsoft\"",
        "tech/stack=sharepoint\\-server"
    },
    {
        "NVT-KEV-CVE-2026-15409",
        "SonicWall SMA1000 Appliances (CVE-2026-15409) KEV Surface & Version Me"
        "tadata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-918",
        "/api/v1/sma1000-appliances/version", 200,
        "\"sma1000-appliances\"", "\"sonicwall\"",
        "tech/stack=sma1000\\-appliances"
    },
    {
        "NVT-KEV-CVE-2026-15410",
        "SonicWall SMA1000 Appliances (CVE-2026-15410) KEV Surface & Version Me"
        "tadata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-94",
        "/api/v1/sma1000-appliances/version", 200,
        "\"sma1000-appliances\"", "\"sonicwall\"",
        "tech/stack=sma1000\\-appliances"
    },
    {
        "NVT-KEV-CVE-2008-4128",
        "Cisco IOS (CVE-2008-4128) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/ios/version", 200,
        "\"ios\"", "\"cisco\"",
        "tech/stack=ios"
    },
    {
        "NVT-KEV-CVE-2026-56291",
        "Balbooa Forms (CVE-2026-56291) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/forms/version", 200,
        "\"forms\"", "\"balbooa\"",
        "tech/stack=forms"
    },
    {
        "NVT-KEV-CVE-2026-48939",
        "iCagenda iCagenda (CVE-2026-48939) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/icagenda/version", 200,
        "\"icagenda\"", "\"icagenda\"",
        "tech/stack=icagenda"
    },
    {
        "NVT-KEV-CVE-2026-48908",
        "JoomShaper SP Page Builder (CVE-2026-48908) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/sp-page-builder/version", 200,
        "\"sp-page-builder\"", "\"joomshaper\"",
        "tech/stack=sp\\-page\\-builder"
    },
    {
        "NVT-KEV-CVE-2026-55255",
        "Langflow Langflow (CVE-2026-55255) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/langflow/version", 200,
        "\"langflow\"", "\"langflow\"",
        "tech/stack=langflow"
    },
    {
        "NVT-KEV-CVE-2026-56290",
        "Joomlack Page Builder (CVE-2026-56290) KEV Surface & Version Metadata "
        "Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/page-builder/version", 200,
        "\"page-builder\"", "\"joomlack\"",
        "tech/stack=page\\-builder"
    },
    {
        "NVT-KEV-CVE-2026-48282",
        "Adobe ColdFusion (CVE-2026-48282) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/coldfusion/version", 200,
        "\"coldfusion\"", "\"adobe\"",
        "tech/stack=coldfusion"
    },
    {
        "NVT-KEV-CVE-2026-45659",
        "Microsoft SharePoint Server (CVE-2026-45659) KEV Surface & Version Met"
        "adata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-502",
        "/api/v1/sharepoint-server/version", 200,
        "\"sharepoint-server\"", "\"microsoft\"",
        "tech/stack=sharepoint\\-server"
    },
    {
        "NVT-KEV-CVE-2026-48558",
        "SimpleHelp SimpleHelp (CVE-2026-48558) KEV Surface & Version Metadata "
        "Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/simplehelp/version", 200,
        "\"simplehelp\"", "\"simplehelp\"",
        "tech/stack=simplehelp"
    },
    {
        "NVT-KEV-CVE-2026-12569",
        "PTC Windchill and FlexPLM (CVE-2026-12569) KEV Surface & Version Metad"
        "ata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-502",
        "/api/v1/windchill-and-flexplm/version", 200,
        "\"windchill-and-flexplm\"", "\"ptc\"",
        "tech/stack=windchill\\-and\\-flexplm"
    },
    {
        "NVT-KEV-CVE-2026-20230",
        "Cisco Unified Communications Manager (CVE-2026-20230) KEV Surface & Ve"
        "rsion Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-918",
        "/api/v1/unified-communications-manager/version", 200,
        "\"unified-communications-manager\"", "\"cisco\"",
        "tech/stack=unified\\-communications\\-manager"
    },
    {
        "NVT-KEV-CVE-2025-67038",
        "Lantronix EDS5000 (CVE-2025-67038) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/eds5000/version", 200,
        "\"eds5000\"", "\"lantronix\"",
        "tech/stack=eds5000"
    },
    {
        "NVT-KEV-CVE-2026-34910",
        "Ubiquiti UniFi OS (CVE-2026-34910) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/unifi-os/version", 200,
        "\"unifi-os\"", "\"ubiquiti\"",
        "tech/stack=unifi\\-os"
    },
    {
        "NVT-KEV-CVE-2026-34909",
        "Ubiquiti UniFi OS (CVE-2026-34909) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/unifi-os/version", 200,
        "\"unifi-os\"", "\"ubiquiti\"",
        "tech/stack=unifi\\-os"
    },
    {
        "NVT-KEV-CVE-2026-34908",
        "Ubiquiti UniFi OS (CVE-2026-34908) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/unifi-os/version", 200,
        "\"unifi-os\"", "\"ubiquiti\"",
        "tech/stack=unifi\\-os"
    },
    {
        "NVT-KEV-CVE-2026-20253",
        "Splunk Enterprise (CVE-2026-20253) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-306",
        "/api/v1/enterprise/version", 200,
        "\"enterprise\"", "\"splunk\"",
        "tech/stack=enterprise"
    },
    {
        "NVT-KEV-CVE-2026-48907",
        "Widget Factory Joomla Content Editor (CVE-2026-48907) KEV Surface & Ve"
        "rsion Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/joomla-content-editor/version", 200,
        "\"joomla-content-editor\"", "\"widget-factory\"",
        "tech/stack=joomla\\-content\\-editor"
    },
    {
        "NVT-KEV-CVE-2026-54420",
        "LiteSpeed cPanel Plugin (CVE-2026-54420) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/cpanel-plugin/version", 200,
        "\"cpanel-plugin\"", "\"litespeed\"",
        "tech/stack=cpanel\\-plugin"
    },
    {
        "NVT-KEV-CVE-2026-20262",
        "Cisco Catalyst SD-WAN Manager (CVE-2026-20262) KEV Surface & Version M"
        "etadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/catalyst-sd-wan-manager/version", 200,
        "\"catalyst-sd-wan-manager\"", "\"cisco\"",
        "tech/stack=catalyst\\-sd\\-wan\\-manager"
    },
    {
        "NVT-KEV-CVE-2026-35273",
        "Oracle PeopleSoft Enterprise PeopleTools (CVE-2026-35273) KEV Surface "
        "& Version Metadata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-306",
        "/api/v1/peoplesoft-enterprise-peopletools/version", 200,
        "\"peoplesoft-enterprise-peopletools\"", "\"oracle\"",
        "tech/stack=peoplesoft\\-enterprise\\-peopletools"
    },
    {
        "NVT-KEV-CVE-2026-10520",
        "Ivanti Sentry (CVE-2026-10520) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/sentry/version", 200,
        "\"sentry\"", "\"ivanti\"",
        "tech/stack=sentry"
    },
    {
        "NVT-KEV-CVE-2026-11645",
        "Google Chromium V8 (CVE-2026-11645) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/chromium-v8/version", 200,
        "\"chromium-v8\"", "\"google\"",
        "tech/stack=chromium\\-v8"
    },
    {
        "NVT-KEV-CVE-2026-7473",
        "Arista Extensible Operating System (CVE-2026-7473) KEV Surface & Versi"
        "on Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/extensible-operating-system/version", 200,
        "\"extensible-operating-system\"", "\"arista\"",
        "tech/stack=extensible\\-operating\\-system"
    },
    {
        "NVT-KEV-CVE-2026-20245",
        "Cisco Catalyst SD-WAN Manager (CVE-2026-20245) KEV Surface & Version M"
        "etadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/catalyst-sd-wan-manager/version", 200,
        "\"catalyst-sd-wan-manager\"", "\"cisco\"",
        "tech/stack=catalyst\\-sd\\-wan\\-manager"
    },
    {
        "NVT-KEV-CVE-2026-42271",
        "BerriAI LiteLLM (CVE-2026-42271) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/litellm/version", 200,
        "\"litellm\"", "\"berriai\"",
        "tech/stack=litellm"
    },
    {
        "NVT-KEV-CVE-2026-50751",
        "Check Point Security Gateway (CVE-2026-50751) KEV Surface & Version Me"
        "tadata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-287",
        "/api/v1/security-gateway/version", 200,
        "\"security-gateway\"", "\"check-point\"",
        "tech/stack=security\\-gateway"
    },
    {
        "NVT-KEV-CVE-2026-28318",
        "SolarWinds Serv-U (CVE-2026-28318) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/serv-u/version", 200,
        "\"serv-u\"", "\"solarwinds\"",
        "tech/stack=serv\\-u"
    },
    {
        "NVT-KEV-CVE-2026-45247",
        "Mirasvit Mirasvit Full Page Cache Warmer (CVE-2026-45247) KEV Surface "
        "& Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-502",
        "/api/v1/mirasvit-full-page-cache-warmer/version", 200,
        "\"mirasvit-full-page-cache-warmer\"", "\"mirasvit\"",
        "tech/stack=mirasvit\\-full\\-page\\-cache\\-warmer"
    },
    {
        "NVT-KEV-CVE-2022-0492",
        "Linux Kernel (CVE-2022-0492) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/kernel/version", 200,
        "\"kernel\"", "\"linux\"",
        "tech/stack=kernel"
    },
    {
        "NVT-KEV-CVE-2025-48595",
        "Android Framework (CVE-2025-48595) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/framework/version", 200,
        "\"framework\"", "\"android\"",
        "tech/stack=framework"
    },
    {
        "NVT-KEV-CVE-2024-21182",
        "Oracle WebLogic Server (CVE-2024-21182) KEV Surface & Version Metadata"
        " Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/weblogic-server/version", 200,
        "\"weblogic-server\"", "\"oracle\"",
        "tech/stack=weblogic\\-server"
    },
    {
        "NVT-KEV-CVE-2026-0257",
        "Palo Alto Networks PAN-OS (CVE-2026-0257) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/pan-os/version", 200,
        "\"pan-os\"", "\"palo-alto-networks\"",
        "tech/stack=pan\\-os"
    },
    {
        "NVT-KEV-CVE-2026-48027",
        "Nx Nx Console (CVE-2026-48027) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/nx-console/version", 200,
        "\"nx-console\"", "\"prod-nx\"",
        "tech/stack=nx\\-console"
    },
    {
        "NVT-KEV-CVE-2026-45321",
        "TanStack TanStack (CVE-2026-45321) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/tanstack/version", 200,
        "\"tanstack\"", "\"tanstack\"",
        "tech/stack=tanstack"
    },
    {
        "NVT-KEV-CVE-2026-8398",
        "Daemon Daemon Tools Lite (CVE-2026-8398) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/daemon-tools-lite/version", 200,
        "\"daemon-tools-lite\"", "\"daemon\"",
        "tech/stack=daemon\\-tools\\-lite"
    },
    {
        "NVT-KEV-CVE-2026-48172",
        "LiteSpeed cPanel Plugin (CVE-2026-48172) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/cpanel-plugin/version", 200,
        "\"cpanel-plugin\"", "\"litespeed\"",
        "tech/stack=cpanel\\-plugin"
    },
    {
        "NVT-KEV-CVE-2026-9082",
        "Drupal Core (CVE-2026-9082) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-89",
        "/api/v1/core/version", 200,
        "\"core\"", "\"drupal\"",
        "tech/stack=core"
    },
    {
        "NVT-KEV-CVE-2025-34291",
        "Langflow Langflow (CVE-2025-34291) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/langflow/version", 200,
        "\"langflow\"", "\"langflow\"",
        "tech/stack=langflow"
    },
    {
        "NVT-KEV-CVE-2026-34926",
        "Trend Micro Apex One (CVE-2026-34926) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/apex-one/version", 200,
        "\"apex-one\"", "\"trend-micro\"",
        "tech/stack=apex\\-one"
    },
    {
        "NVT-KEV-CVE-2008-4250",
        "Microsoft Windows (CVE-2008-4250) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2009-1537",
        "Microsoft DirectX (CVE-2009-1537) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/directx/version", 200,
        "\"directx\"", "\"microsoft\"",
        "tech/stack=directx"
    },
    {
        "NVT-KEV-CVE-2009-3459",
        "Adobe Acrobat and Reader (CVE-2009-3459) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/acrobat-and-reader/version", 200,
        "\"acrobat-and-reader\"", "\"adobe\"",
        "tech/stack=acrobat\\-and\\-reader"
    },
    {
        "NVT-KEV-CVE-2010-0249",
        "Microsoft Internet Explorer (CVE-2010-0249) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/internet-explorer/version", 200,
        "\"internet-explorer\"", "\"microsoft\"",
        "tech/stack=internet\\-explorer"
    },
    {
        "NVT-KEV-CVE-2010-0806",
        "Microsoft Internet Explorer (CVE-2010-0806) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/internet-explorer/version", 200,
        "\"internet-explorer\"", "\"microsoft\"",
        "tech/stack=internet\\-explorer"
    },
    {
        "NVT-KEV-CVE-2026-41091",
        "Microsoft Defender (CVE-2026-41091) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/defender/version", 200,
        "\"defender\"", "\"microsoft\"",
        "tech/stack=defender"
    },
    {
        "NVT-KEV-CVE-2026-45498",
        "Microsoft Defender (CVE-2026-45498) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/defender/version", 200,
        "\"defender\"", "\"microsoft\"",
        "tech/stack=defender"
    },
    {
        "NVT-KEV-CVE-2026-42897",
        "Microsoft Microsoft (CVE-2026-42897) KEV Surface & Version Metadata Ex"
        "posure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-79",
        "/api/v1/microsoft/version", 200,
        "\"microsoft\"", "\"microsoft\"",
        "tech/stack=microsoft"
    },
    {
        "NVT-KEV-CVE-2026-20182",
        "Cisco Catalyst SD-WAN (CVE-2026-20182) KEV Surface & Version Metadata "
        "Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/catalyst-sd-wan/version", 200,
        "\"catalyst-sd-wan\"", "\"cisco\"",
        "tech/stack=catalyst\\-sd\\-wan"
    },
    {
        "NVT-KEV-CVE-2026-42208",
        "BerriAI LiteLLM (CVE-2026-42208) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-89",
        "/api/v1/litellm/version", 200,
        "\"litellm\"", "\"berriai\"",
        "tech/stack=litellm"
    },
    {
        "NVT-KEV-CVE-2026-6973",
        "Ivanti Endpoint Manager Mobile (EPMM) (CVE-2026-6973) KEV Surface & Ve"
        "rsion Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/endpoint-manager-mobile-epmm/version", 200,
        "\"endpoint-manager-mobile-epmm\"", "\"ivanti\"",
        "tech/stack=endpoint\\-manager\\-mobile\\-epmm"
    },
    {
        "NVT-KEV-CVE-2026-0300",
        "Palo Alto Networks PAN-OS (CVE-2026-0300) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/pan-os/version", 200,
        "\"pan-os\"", "\"palo-alto-networks\"",
        "tech/stack=pan\\-os"
    },
    {
        "NVT-KEV-CVE-2026-31431",
        "Linux Kernel (CVE-2026-31431) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/kernel/version", 200,
        "\"kernel\"", "\"linux\"",
        "tech/stack=kernel"
    },
    {
        "NVT-KEV-CVE-2026-41940",
        "WebPros cPanel & WHM and WP2 (WordPress Squared) (CVE-2026-41940) KEV "
        "Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-306",
        "/api/v1/cpanel-whm-and-wp2-wordpress-squared/version", 200,
        "\"cpanel-whm-and-wp2-wordpress-squared\"", "\"webpros\"",
        "tech/stack=cpanel\\-whm\\-and\\-wp2\\-wordpress\\-squared"
    },
    {
        "NVT-KEV-CVE-2024-1708",
        "ConnectWise ScreenConnect (CVE-2024-1708) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-22",
        "/api/v1/screenconnect/version", 200,
        "\"screenconnect\"", "\"connectwise\"",
        "tech/stack=screenconnect"
    },
    {
        "NVT-KEV-CVE-2026-32202",
        "Microsoft Windows (CVE-2026-32202) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-29635",
        "D-Link DIR-823X (CVE-2025-29635) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/dir-823x/version", 200,
        "\"dir-823x\"", "\"d-link\"",
        "tech/stack=dir\\-823x"
    },
    {
        "NVT-KEV-CVE-2024-7399",
        "Samsung MagicINFO 9 Server (CVE-2024-7399) KEV Surface & Version Metad"
        "ata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/magicinfo-9-server/version", 200,
        "\"magicinfo-9-server\"", "\"samsung\"",
        "tech/stack=magicinfo\\-9\\-server"
    },
    {
        "NVT-KEV-CVE-2024-57728",
        "SimpleHelp SimpleHelp (CVE-2024-57728) KEV Surface & Version Metadata "
        "Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-22",
        "/api/v1/simplehelp/version", 200,
        "\"simplehelp\"", "\"simplehelp\"",
        "tech/stack=simplehelp"
    },
    {
        "NVT-KEV-CVE-2024-57726",
        "SimpleHelp SimpleHelp (CVE-2024-57726) KEV Surface & Version Metadata "
        "Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-284",
        "/api/v1/simplehelp/version", 200,
        "\"simplehelp\"", "\"simplehelp\"",
        "tech/stack=simplehelp"
    },
    {
        "NVT-KEV-CVE-2026-39987",
        "Marimo Marimo (CVE-2026-39987) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-306",
        "/api/v1/marimo/version", 200,
        "\"marimo\"", "\"marimo\"",
        "tech/stack=marimo"
    },
    {
        "NVT-KEV-CVE-2026-33825",
        "Microsoft Defender (CVE-2026-33825) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/defender/version", 200,
        "\"defender\"", "\"microsoft\"",
        "tech/stack=defender"
    },
    {
        "NVT-KEV-CVE-2026-20122",
        "Cisco Catalyst SD-WAN Manger (CVE-2026-20122) KEV Surface & Version Me"
        "tadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/catalyst-sd-wan-manger/version", 200,
        "\"catalyst-sd-wan-manger\"", "\"cisco\"",
        "tech/stack=catalyst\\-sd\\-wan\\-manger"
    },
    {
        "NVT-KEV-CVE-2026-20133",
        "Cisco Catalyst SD-WAN Manager (CVE-2026-20133) KEV Surface & Version M"
        "etadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-200",
        "/api/v1/catalyst-sd-wan-manager/version", 200,
        "\"catalyst-sd-wan-manager\"", "\"cisco\"",
        "tech/stack=catalyst\\-sd\\-wan\\-manager"
    },
    {
        "NVT-KEV-CVE-2025-2749",
        "Kentico Kentico Xperience (CVE-2025-2749) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/kentico-xperience/version", 200,
        "\"kentico-xperience\"", "\"kentico\"",
        "tech/stack=kentico\\-xperience"
    },
    {
        "NVT-KEV-CVE-2023-27351",
        "PaperCut NG/MF (CVE-2023-27351) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-287",
        "/api/v1/ng-mf/version", 200,
        "\"ng-mf\"", "\"papercut\"",
        "tech/stack=ng\\-mf"
    },
    {
        "NVT-KEV-CVE-2025-48700",
        "Synacor Zimbra Collaboration Suite (ZCS) (CVE-2025-48700) KEV Surface "
        "& Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-79",
        "/api/v1/zimbra-collaboration-suite-zcs/version", 200,
        "\"zimbra-collaboration-suite-zcs\"", "\"synacor\"",
        "tech/stack=zimbra\\-collaboration\\-suite\\-zcs"
    },
    {
        "NVT-KEV-CVE-2026-20128",
        "Cisco Catalyst SD-WAN Manager (CVE-2026-20128) KEV Surface & Version M"
        "etadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/catalyst-sd-wan-manager/version", 200,
        "\"catalyst-sd-wan-manager\"", "\"cisco\"",
        "tech/stack=catalyst\\-sd\\-wan\\-manager"
    },
    {
        "NVT-KEV-CVE-2025-32975",
        "Quest KACE Systems Management Appliance (SMA) (CVE-2025-32975) KEV Sur"
        "face & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/kace-systems-management-appliance-sm/version", 200,
        "\"kace-systems-management-appliance-sm\"", "\"quest\"",
        "tech/stack=kace\\-systems\\-management\\-appliance\\-sm"
    },
    {
        "NVT-KEV-CVE-2024-27199",
        "JetBrains TeamCity (CVE-2024-27199) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/teamcity/version", 200,
        "\"teamcity\"", "\"jetbrains\"",
        "tech/stack=teamcity"
    },
    {
        "NVT-KEV-CVE-2026-34197",
        "Apache ActiveMQ (CVE-2026-34197) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/activemq/version", 200,
        "\"activemq\"", "\"apache\"",
        "tech/stack=activemq"
    },
    {
        "NVT-KEV-CVE-2009-0238",
        "Microsoft Office (CVE-2009-0238) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/office/version", 200,
        "\"office\"", "\"microsoft\"",
        "tech/stack=office"
    },
    {
        "NVT-KEV-CVE-2026-32201",
        "Microsoft SharePoint Server (CVE-2026-32201) KEV Surface & Version Met"
        "adata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/sharepoint-server/version", 200,
        "\"sharepoint-server\"", "\"microsoft\"",
        "tech/stack=sharepoint\\-server"
    },
    {
        "NVT-KEV-CVE-2012-1854",
        "Microsoft Visual Basic for Applications (VBA) (CVE-2012-1854) KEV Surf"
        "ace & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/visual-basic-for-applications-vba/version", 200,
        "\"visual-basic-for-applications-vba\"", "\"microsoft\"",
        "tech/stack=visual\\-basic\\-for\\-applications\\-vba"
    },
    {
        "NVT-KEV-CVE-2025-60710",
        "Microsoft Windows (CVE-2025-60710) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2023-21529",
        "Microsoft Exchange Server (CVE-2023-21529) KEV Surface & Version Metad"
        "ata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-502",
        "/api/v1/exchange-server/version", 200,
        "\"exchange-server\"", "\"microsoft\"",
        "tech/stack=exchange\\-server"
    },
    {
        "NVT-KEV-CVE-2023-36424",
        "Microsoft Windows (CVE-2023-36424) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2020-9715",
        "Adobe Acrobat (CVE-2020-9715) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/acrobat/version", 200,
        "\"acrobat\"", "\"adobe\"",
        "tech/stack=acrobat"
    },
    {
        "NVT-KEV-CVE-2026-21643",
        "Fortinet FortiClient EMS (CVE-2026-21643) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-89",
        "/api/v1/forticlient-ems/version", 200,
        "\"forticlient-ems\"", "\"fortinet\"",
        "tech/stack=forticlient\\-ems"
    },
    {
        "NVT-KEV-CVE-2026-34621",
        "Adobe Acrobat and Reader (CVE-2026-34621) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/acrobat-and-reader/version", 200,
        "\"acrobat-and-reader\"", "\"adobe\"",
        "tech/stack=acrobat\\-and\\-reader"
    },
    {
        "NVT-KEV-CVE-2026-1340",
        "Ivanti Endpoint Manager Mobile (EPMM) (CVE-2026-1340) KEV Surface & Ve"
        "rsion Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/endpoint-manager-mobile-epmm/version", 200,
        "\"endpoint-manager-mobile-epmm\"", "\"ivanti\"",
        "tech/stack=endpoint\\-manager\\-mobile\\-epmm"
    },
    {
        "NVT-KEV-CVE-2026-35616",
        "Fortinet FortiClient EMS (CVE-2026-35616) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/forticlient-ems/version", 200,
        "\"forticlient-ems\"", "\"fortinet\"",
        "tech/stack=forticlient\\-ems"
    },
    {
        "NVT-KEV-CVE-2026-3502",
        "TrueConf Client (CVE-2026-3502) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/client/version", 200,
        "\"client\"", "\"trueconf\"",
        "tech/stack=client"
    },
    {
        "NVT-KEV-CVE-2026-5281",
        "Google Dawn (CVE-2026-5281) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/dawn/version", 200,
        "\"dawn\"", "\"google\"",
        "tech/stack=dawn"
    },
    {
        "NVT-KEV-CVE-2026-3055",
        "Citrix NetScaler (CVE-2026-3055) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/netscaler/version", 200,
        "\"netscaler\"", "\"citrix\"",
        "tech/stack=netscaler"
    },
    {
        "NVT-KEV-CVE-2025-53521",
        "F5 BIG-IP (CVE-2025-53521) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/big-ip/version", 200,
        "\"big-ip\"", "\"prod-f5\"",
        "tech/stack=big\\-ip"
    },
    {
        "NVT-KEV-CVE-2026-33634",
        "Aquasecurity Trivy (CVE-2026-33634) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/trivy/version", 200,
        "\"trivy\"", "\"aquasecurity\"",
        "tech/stack=trivy"
    },
    {
        "NVT-KEV-CVE-2026-33017",
        "Langflow Langflow (CVE-2026-33017) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/langflow/version", 200,
        "\"langflow\"", "\"langflow\"",
        "tech/stack=langflow"
    },
    {
        "NVT-KEV-CVE-2025-32432",
        "Craft CMS Craft CMS (CVE-2025-32432) KEV Surface & Version Metadata Ex"
        "posure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/craft-cms/version", 200,
        "\"craft-cms\"", "\"craft-cms\"",
        "tech/stack=craft\\-cms"
    },
    {
        "NVT-KEV-CVE-2025-54068",
        "Laravel Livewire (CVE-2025-54068) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/livewire/version", 200,
        "\"livewire\"", "\"laravel\"",
        "tech/stack=livewire"
    },
    {
        "NVT-KEV-CVE-2025-43510",
        "Apple Multiple Products (CVE-2025-43510) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"apple\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2025-43520",
        "Apple Multiple Products (CVE-2025-43520) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"apple\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2025-31277",
        "Apple Multiple Products (CVE-2025-31277) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"apple\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2026-20131",
        "Cisco Secure Firewall Management Center (FMC) (CVE-2026-20131) KEV Sur"
        "face & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-502",
        "/api/v1/secure-firewall-management-center-fm/version", 200,
        "\"secure-firewall-management-center-fm\"", "\"cisco\"",
        "tech/stack=secure\\-firewall\\-management\\-center\\-fm"
    },
    {
        "NVT-KEV-CVE-2025-66376",
        "Synacor Zimbra Collaboration Suite (ZCS) (CVE-2025-66376) KEV Surface "
        "& Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-79",
        "/api/v1/zimbra-collaboration-suite-zcs/version", 200,
        "\"zimbra-collaboration-suite-zcs\"", "\"synacor\"",
        "tech/stack=zimbra\\-collaboration\\-suite\\-zcs"
    },
    {
        "NVT-KEV-CVE-2026-20963",
        "Microsoft SharePoint (CVE-2026-20963) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-502",
        "/api/v1/sharepoint/version", 200,
        "\"sharepoint\"", "\"microsoft\"",
        "tech/stack=sharepoint"
    },
    {
        "NVT-KEV-CVE-2025-47813",
        "Wing FTP Server Wing FTP Server (CVE-2025-47813) KEV Surface & Version"
        " Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/wing-ftp-server/version", 200,
        "\"wing-ftp-server\"", "\"wing-ftp-server\"",
        "tech/stack=wing\\-ftp\\-server"
    },
    {
        "NVT-KEV-CVE-2026-3910",
        "Google Chromium V8 (CVE-2026-3910) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/chromium-v8/version", 200,
        "\"chromium-v8\"", "\"google\"",
        "tech/stack=chromium\\-v8"
    },
    {
        "NVT-KEV-CVE-2026-3909",
        "Google Skia (CVE-2026-3909) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/skia/version", 200,
        "\"skia\"", "\"google\"",
        "tech/stack=skia"
    },
    {
        "NVT-KEV-CVE-2025-68613",
        "n8n n8n (CVE-2025-68613) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/n8n/version", 200,
        "\"n8n\"", "\"n8n\"",
        "tech/stack=n8n"
    },
    {
        "NVT-KEV-CVE-2021-22054",
        "Omnissa Workspace One UEM (CVE-2021-22054) KEV Surface & Version Metad"
        "ata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-918",
        "/api/v1/workspace-one-uem/version", 200,
        "\"workspace-one-uem\"", "\"omnissa\"",
        "tech/stack=workspace\\-one\\-uem"
    },
    {
        "NVT-KEV-CVE-2025-26399",
        "SolarWinds Web Help Desk (CVE-2025-26399) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-502",
        "/api/v1/web-help-desk/version", 200,
        "\"web-help-desk\"", "\"solarwinds\"",
        "tech/stack=web\\-help\\-desk"
    },
    {
        "NVT-KEV-CVE-2026-1603",
        "Ivanti Endpoint Manager (EPM) (CVE-2026-1603) KEV Surface & Version Me"
        "tadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/endpoint-manager-epm/version", 200,
        "\"endpoint-manager-epm\"", "\"ivanti\"",
        "tech/stack=endpoint\\-manager\\-epm"
    },
    {
        "NVT-KEV-CVE-2017-7921",
        "Hikvision Multiple Products (CVE-2017-7921) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"hikvision\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2021-22681",
        "Rockwell Multiple Products (CVE-2021-22681) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"rockwell\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2023-43000",
        "Apple Multiple Products (CVE-2023-43000) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"apple\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2021-30952",
        "Apple Multiple Products (CVE-2021-30952) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"apple\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2023-41974",
        "Apple iOS and iPadOS (CVE-2023-41974) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/ios-and-ipados/version", 200,
        "\"ios-and-ipados\"", "\"apple\"",
        "tech/stack=ios\\-and\\-ipados"
    },
    {
        "NVT-KEV-CVE-2026-22719",
        "Broadcom VMware Aria Operations (CVE-2026-22719) KEV Surface & Version"
        " Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/vmware-aria-operations/version", 200,
        "\"vmware-aria-operations\"", "\"broadcom\"",
        "tech/stack=vmware\\-aria\\-operations"
    },
    {
        "NVT-KEV-CVE-2026-21385",
        "Qualcomm Multiple Chipsets (CVE-2026-21385) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-chipsets/version", 200,
        "\"multiple-chipsets\"", "\"qualcomm\"",
        "tech/stack=multiple\\-chipsets"
    },
    {
        "NVT-KEV-CVE-2022-20775",
        "Cisco SD-WAN (CVE-2022-20775) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/sd-wan/version", 200,
        "\"sd-wan\"", "\"cisco\"",
        "tech/stack=sd\\-wan"
    },
    {
        "NVT-KEV-CVE-2026-20127",
        "Cisco Catalyst SD-WAN Controller and Manager (CVE-2026-20127) KEV Surf"
        "ace & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/catalyst-sd-wan-controller-and-manag/version", 200,
        "\"catalyst-sd-wan-controller-and-manag\"", "\"cisco\"",
        "tech/stack=catalyst\\-sd\\-wan\\-controller\\-and\\-manag"
    },
    {
        "NVT-KEV-CVE-2026-25108",
        "Soliton Systems K.K FileZen (CVE-2026-25108) KEV Surface & Version Met"
        "adata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/filezen/version", 200,
        "\"filezen\"", "\"soliton-systems-k-k\"",
        "tech/stack=filezen"
    },
    {
        "NVT-KEV-CVE-2025-49113",
        "Roundcube Webmail (CVE-2025-49113) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-502",
        "/api/v1/webmail/version", 200,
        "\"webmail\"", "\"roundcube\"",
        "tech/stack=webmail"
    },
    {
        "NVT-KEV-CVE-2025-68461",
        "Roundcube Webmail (CVE-2025-68461) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-79",
        "/api/v1/webmail/version", 200,
        "\"webmail\"", "\"roundcube\"",
        "tech/stack=webmail"
    },
    {
        "NVT-KEV-CVE-2021-22175",
        "GitLab GitLab (CVE-2021-22175) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-918",
        "/api/v1/gitlab/version", 200,
        "\"gitlab\"", "\"gitlab\"",
        "tech/stack=gitlab"
    },
    {
        "NVT-KEV-CVE-2026-22769",
        "Dell RecoverPoint for Virtual Machines (RP4VMs) (CVE-2026-22769) KEV S"
        "urface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-798",
        "/api/v1/recoverpoint-for-virtual-machines-rp/version", 200,
        "\"recoverpoint-for-virtual-machines-rp\"", "\"dell\"",
        "tech/stack=recoverpoint\\-for\\-virtual\\-machines\\-rp"
    },
    {
        "NVT-KEV-CVE-2020-7796",
        "Synacor Zimbra Collaboration Suite (CVE-2020-7796) KEV Surface & Versi"
        "on Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-918",
        "/api/v1/zimbra-collaboration-suite/version", 200,
        "\"zimbra-collaboration-suite\"", "\"synacor\"",
        "tech/stack=zimbra\\-collaboration\\-suite"
    },
    {
        "NVT-KEV-CVE-2024-7694",
        "TeamT5 ThreatSonar Anti-Ransomware (CVE-2024-7694) KEV Surface & Versi"
        "on Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/threatsonar-anti-ransomware/version", 200,
        "\"threatsonar-anti-ransomware\"", "\"teamt5\"",
        "tech/stack=threatsonar\\-anti\\-ransomware"
    },
    {
        "NVT-KEV-CVE-2008-0015",
        "Microsoft Windows (CVE-2008-0015) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2026-2441",
        "Google Chromium (CVE-2026-2441) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/chromium/version", 200,
        "\"chromium\"", "\"google\"",
        "tech/stack=chromium"
    },
    {
        "NVT-KEV-CVE-2026-1731",
        "BeyondTrust Remote Support (RS) and Privileged Remote Access (PRA) (CV"
        "E-2026-1731) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-78",
        "/api/v1/remote-support-rs-and-privileged-rem/version", 200,
        "\"remote-support-rs-and-privileged-rem\"", "\"beyondtrust\"",
        "tech/stack=remote\\-support\\-rs\\-and\\-privileged\\-rem"
    },
    {
        "NVT-KEV-CVE-2026-20700",
        "Apple Multiple Products (CVE-2026-20700) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"apple\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2024-43468",
        "Microsoft Configuration Manager (CVE-2024-43468) KEV Surface & Version"
        " Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-89",
        "/api/v1/configuration-manager/version", 200,
        "\"configuration-manager\"", "\"microsoft\"",
        "tech/stack=configuration\\-manager"
    },
    {
        "NVT-KEV-CVE-2025-15556",
        "Notepad++ Notepad++ (CVE-2025-15556) KEV Surface & Version Metadata Ex"
        "posure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/notepad/version", 200,
        "\"notepad\"", "\"notepad\"",
        "tech/stack=notepad"
    },
    {
        "NVT-KEV-CVE-2025-40536",
        "SolarWinds Web Help Desk (CVE-2025-40536) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/web-help-desk/version", 200,
        "\"web-help-desk\"", "\"solarwinds\"",
        "tech/stack=web\\-help\\-desk"
    },
    {
        "NVT-KEV-CVE-2026-21513",
        "Microsoft Windows (CVE-2026-21513) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2026-21525",
        "Microsoft Windows (CVE-2026-21525) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2026-21510",
        "Microsoft Windows (CVE-2026-21510) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2026-21533",
        "Microsoft Windows (CVE-2026-21533) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2026-21519",
        "Microsoft Windows (CVE-2026-21519) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2026-21514",
        "Microsoft Office (CVE-2026-21514) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/office/version", 200,
        "\"office\"", "\"microsoft\"",
        "tech/stack=office"
    },
    {
        "NVT-KEV-CVE-2025-11953",
        "React Native Community CLI (CVE-2025-11953) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/cli/version", 200,
        "\"cli\"", "\"react-native-community\"",
        "tech/stack=cli"
    },
    {
        "NVT-KEV-CVE-2026-24423",
        "SmarterTools SmarterMail (CVE-2026-24423) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-306",
        "/api/v1/smartermail/version", 200,
        "\"smartermail\"", "\"smartertools\"",
        "tech/stack=smartermail"
    },
    {
        "NVT-KEV-CVE-2021-39935",
        "GitLab Community and Enterprise Editions (CVE-2021-39935) KEV Surface "
        "& Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-918",
        "/api/v1/community-and-enterprise-editions/version", 200,
        "\"community-and-enterprise-editions\"", "\"gitlab\"",
        "tech/stack=community\\-and\\-enterprise\\-editions"
    },
    {
        "NVT-KEV-CVE-2025-64328",
        "Sangoma FreePBX (CVE-2025-64328) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/freepbx/version", 200,
        "\"freepbx\"", "\"sangoma\"",
        "tech/stack=freepbx"
    },
    {
        "NVT-KEV-CVE-2019-19006",
        "Sangoma FreePBX (CVE-2019-19006) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/freepbx/version", 200,
        "\"freepbx\"", "\"sangoma\"",
        "tech/stack=freepbx"
    },
    {
        "NVT-KEV-CVE-2025-40551",
        "SolarWinds Web Help Desk (CVE-2025-40551) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-502",
        "/api/v1/web-help-desk/version", 200,
        "\"web-help-desk\"", "\"solarwinds\"",
        "tech/stack=web\\-help\\-desk"
    },
    {
        "NVT-KEV-CVE-2026-1281",
        "Ivanti Endpoint Manager Mobile (EPMM) (CVE-2026-1281) KEV Surface & Ve"
        "rsion Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/endpoint-manager-mobile-epmm/version", 200,
        "\"endpoint-manager-mobile-epmm\"", "\"ivanti\"",
        "tech/stack=endpoint\\-manager\\-mobile\\-epmm"
    },
    {
        "NVT-KEV-CVE-2026-24858",
        "Fortinet Multiple Products (CVE-2026-24858) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"fortinet\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2018-14634",
        "Linux Kernel (CVE-2018-14634) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/kernel/version", 200,
        "\"kernel\"", "\"linux\"",
        "tech/stack=kernel"
    },
    {
        "NVT-KEV-CVE-2025-52691",
        "SmarterTools SmarterMail (CVE-2025-52691) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/smartermail/version", 200,
        "\"smartermail\"", "\"smartertools\"",
        "tech/stack=smartermail"
    },
    {
        "NVT-KEV-CVE-2026-23760",
        "SmarterTools SmarterMail (CVE-2026-23760) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-287",
        "/api/v1/smartermail/version", 200,
        "\"smartermail\"", "\"smartertools\"",
        "tech/stack=smartermail"
    },
    {
        "NVT-KEV-CVE-2026-24061",
        "GNU InetUtils (CVE-2026-24061) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/inetutils/version", 200,
        "\"inetutils\"", "\"gnu\"",
        "tech/stack=inetutils"
    },
    {
        "NVT-KEV-CVE-2026-21509",
        "Microsoft Office (CVE-2026-21509) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/office/version", 200,
        "\"office\"", "\"microsoft\"",
        "tech/stack=office"
    },
    {
        "NVT-KEV-CVE-2024-37079",
        "Broadcom VMware vCenter Server (CVE-2024-37079) KEV Surface & Version "
        "Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/vmware-vcenter-server/version", 200,
        "\"vmware-vcenter-server\"", "\"broadcom\"",
        "tech/stack=vmware\\-vcenter\\-server"
    },
    {
        "NVT-KEV-CVE-2025-68645",
        "Synacor Zimbra Collaboration Suite (ZCS) (CVE-2025-68645) KEV Surface "
        "& Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/zimbra-collaboration-suite-zcs/version", 200,
        "\"zimbra-collaboration-suite-zcs\"", "\"synacor\"",
        "tech/stack=zimbra\\-collaboration\\-suite\\-zcs"
    },
    {
        "NVT-KEV-CVE-2025-34026",
        "Versa Concerto (CVE-2025-34026) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/concerto/version", 200,
        "\"concerto\"", "\"versa\"",
        "tech/stack=concerto"
    },
    {
        "NVT-KEV-CVE-2025-31125",
        "Vite Vitejs (CVE-2025-31125) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-200",
        "/api/v1/vitejs/version", 200,
        "\"vitejs\"", "\"vite\"",
        "tech/stack=vitejs"
    },
    {
        "NVT-KEV-CVE-2025-54313",
        "Prettier eslint-config-prettier (CVE-2025-54313) KEV Surface & Version"
        " Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/eslint-config-prettier/version", 200,
        "\"eslint-config-prettier\"", "\"prettier\"",
        "tech/stack=eslint\\-config\\-prettier"
    },
    {
        "NVT-KEV-CVE-2026-20045",
        "Cisco Unified Communications Manager (CVE-2026-20045) KEV Surface & Ve"
        "rsion Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/unified-communications-manager/version", 200,
        "\"unified-communications-manager\"", "\"cisco\"",
        "tech/stack=unified\\-communications\\-manager"
    },
    {
        "NVT-KEV-CVE-2026-20805",
        "Microsoft Windows (CVE-2026-20805) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-200",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-8110",
        "Gogs Gogs (CVE-2025-8110) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/gogs/version", 200,
        "\"gogs\"", "\"gogs\"",
        "tech/stack=gogs"
    },
    {
        "NVT-KEV-CVE-2009-0556",
        "Microsoft Office (CVE-2009-0556) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/office/version", 200,
        "\"office\"", "\"microsoft\"",
        "tech/stack=office"
    },
    {
        "NVT-KEV-CVE-2025-37164",
        "Hewlett Packard Enterprise (HPE) OneView (CVE-2025-37164) KEV Surface "
        "& Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/oneview/version", 200,
        "\"oneview\"", "\"hewlett-packard-enterprise-hpe\"",
        "tech/stack=oneview"
    },
    {
        "NVT-KEV-CVE-2025-14847",
        "MongoDB MongoDB and MongoDB Server (CVE-2025-14847) KEV Surface & Vers"
        "ion Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/mongodb-and-mongodb-server/version", 200,
        "\"mongodb-and-mongodb-server\"", "\"mongodb\"",
        "tech/stack=mongodb\\-and\\-mongodb\\-server"
    },
    {
        "NVT-KEV-CVE-2023-52163",
        "Digiever DS-2105 Pro (CVE-2023-52163) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/ds-2105-pro/version", 200,
        "\"ds-2105-pro\"", "\"digiever\"",
        "tech/stack=ds\\-2105\\-pro"
    },
    {
        "NVT-KEV-CVE-2025-14733",
        "WatchGuard Firebox (CVE-2025-14733) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/firebox/version", 200,
        "\"firebox\"", "\"watchguard\"",
        "tech/stack=firebox"
    },
    {
        "NVT-KEV-CVE-2025-59374",
        "ASUS Live Update (CVE-2025-59374) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/live-update/version", 200,
        "\"live-update\"", "\"asus\"",
        "tech/stack=live\\-update"
    },
    {
        "NVT-KEV-CVE-2025-40602",
        "SonicWall SMA1000 appliance (CVE-2025-40602) KEV Surface & Version Met"
        "adata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/sma1000-appliance/version", 200,
        "\"sma1000-appliance\"", "\"sonicwall\"",
        "tech/stack=sma1000\\-appliance"
    },
    {
        "NVT-KEV-CVE-2025-20393",
        "Cisco Multiple Products (CVE-2025-20393) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"cisco\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2025-59718",
        "Fortinet Multiple Products (CVE-2025-59718) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"fortinet\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2025-14611",
        "Gladinet CentreStack and Triofox (CVE-2025-14611) KEV Surface & Versio"
        "n Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-798",
        "/api/v1/centrestack-and-triofox/version", 200,
        "\"centrestack-and-triofox\"", "\"gladinet\"",
        "tech/stack=centrestack\\-and\\-triofox"
    },
    {
        "NVT-KEV-CVE-2025-43529",
        "Apple Multiple Products (CVE-2025-43529) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"apple\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2018-4063",
        "Sierra Wireless AirLink ALEOS (CVE-2018-4063) KEV Surface & Version Me"
        "tadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/airlink-aleos/version", 200,
        "\"airlink-aleos\"", "\"sierra-wireless\"",
        "tech/stack=airlink\\-aleos"
    },
    {
        "NVT-KEV-CVE-2025-14174",
        "Google Chromium (CVE-2025-14174) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/chromium/version", 200,
        "\"chromium\"", "\"google\"",
        "tech/stack=chromium"
    },
    {
        "NVT-KEV-CVE-2025-58360",
        "OSGeo GeoServer (CVE-2025-58360) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/geoserver/version", 200,
        "\"geoserver\"", "\"osgeo\"",
        "tech/stack=geoserver"
    },
    {
        "NVT-KEV-CVE-2025-6218",
        "RARLAB WinRAR (CVE-2025-6218) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/winrar/version", 200,
        "\"winrar\"", "\"rarlab\"",
        "tech/stack=winrar"
    },
    {
        "NVT-KEV-CVE-2025-62221",
        "Microsoft Windows (CVE-2025-62221) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2022-37055",
        "D-Link Routers (CVE-2022-37055) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/routers/version", 200,
        "\"routers\"", "\"d-link\"",
        "tech/stack=routers"
    },
    {
        "NVT-KEV-CVE-2025-66644",
        "Array Networks ArrayOS AG (CVE-2025-66644) KEV Surface & Version Metad"
        "ata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/arrayos-ag/version", 200,
        "\"arrayos-ag\"", "\"array-networks\"",
        "tech/stack=arrayos\\-ag"
    },
    {
        "NVT-KEV-CVE-2025-55182",
        "Meta React Server Components (CVE-2025-55182) KEV Surface & Version Me"
        "tadata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/react-server-components/version", 200,
        "\"react-server-components\"", "\"meta\"",
        "tech/stack=react\\-server\\-components"
    },
    {
        "NVT-KEV-CVE-2021-26828",
        "OpenPLC ScadaBR (CVE-2021-26828) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/scadabr/version", 200,
        "\"scadabr\"", "\"openplc\"",
        "tech/stack=scadabr"
    },
    {
        "NVT-KEV-CVE-2025-48633",
        "Android Framework (CVE-2025-48633) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/framework/version", 200,
        "\"framework\"", "\"android\"",
        "tech/stack=framework"
    },
    {
        "NVT-KEV-CVE-2025-48572",
        "Android Framework (CVE-2025-48572) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/framework/version", 200,
        "\"framework\"", "\"android\"",
        "tech/stack=framework"
    },
    {
        "NVT-KEV-CVE-2021-26829",
        "OpenPLC ScadaBR (CVE-2021-26829) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-79",
        "/api/v1/scadabr/version", 200,
        "\"scadabr\"", "\"openplc\"",
        "tech/stack=scadabr"
    },
    {
        "NVT-KEV-CVE-2025-61757",
        "Oracle Fusion Middleware (CVE-2025-61757) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-306",
        "/api/v1/fusion-middleware/version", 200,
        "\"fusion-middleware\"", "\"oracle\"",
        "tech/stack=fusion\\-middleware"
    },
    {
        "NVT-KEV-CVE-2025-13223",
        "Google Chromium V8 (CVE-2025-13223) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/chromium-v8/version", 200,
        "\"chromium-v8\"", "\"google\"",
        "tech/stack=chromium\\-v8"
    },
    {
        "NVT-KEV-CVE-2025-58034",
        "Fortinet FortiWeb (CVE-2025-58034) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/fortiweb/version", 200,
        "\"fortiweb\"", "\"fortinet\"",
        "tech/stack=fortiweb"
    },
    {
        "NVT-KEV-CVE-2025-64446",
        "Fortinet FortiWeb (CVE-2025-64446) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/fortiweb/version", 200,
        "\"fortiweb\"", "\"fortinet\"",
        "tech/stack=fortiweb"
    },
    {
        "NVT-KEV-CVE-2025-12480",
        "Gladinet Triofox (CVE-2025-12480) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/triofox/version", 200,
        "\"triofox\"", "\"gladinet\"",
        "tech/stack=triofox"
    },
    {
        "NVT-KEV-CVE-2025-62215",
        "Microsoft Windows (CVE-2025-62215) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-9242",
        "WatchGuard Firebox (CVE-2025-9242) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/firebox/version", 200,
        "\"firebox\"", "\"watchguard\"",
        "tech/stack=firebox"
    },
    {
        "NVT-KEV-CVE-2025-21042",
        "Samsung Mobile Devices (CVE-2025-21042) KEV Surface & Version Metadata"
        " Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/mobile-devices/version", 200,
        "\"mobile-devices\"", "\"samsung\"",
        "tech/stack=mobile\\-devices"
    },
    {
        "NVT-KEV-CVE-2025-48703",
        "CWP Control Web Panel (CVE-2025-48703) KEV Surface & Version Metadata "
        "Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/control-web-panel/version", 200,
        "\"control-web-panel\"", "\"cwp\"",
        "tech/stack=control\\-web\\-panel"
    },
    {
        "NVT-KEV-CVE-2025-11371",
        "Gladinet CentreStack and Triofox (CVE-2025-11371) KEV Surface & Versio"
        "n Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/centrestack-and-triofox/version", 200,
        "\"centrestack-and-triofox\"", "\"gladinet\"",
        "tech/stack=centrestack\\-and\\-triofox"
    },
    {
        "NVT-KEV-CVE-2025-41244",
        "Broadcom VMware Aria Operations and VMware Tools (CVE-2025-41244) KEV "
        "Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/vmware-aria-operations-and-vmware-to/version", 200,
        "\"vmware-aria-operations-and-vmware-to\"", "\"broadcom\"",
        "tech/stack=vmware\\-aria\\-operations\\-and\\-vmware\\-to"
    },
    {
        "NVT-KEV-CVE-2025-24893",
        "XWiki Platform (CVE-2025-24893) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/platform/version", 200,
        "\"platform\"", "\"xwiki\"",
        "tech/stack=platform"
    },
    {
        "NVT-KEV-CVE-2025-6204",
        "Dassault Systèmes DELMIA Apriso (CVE-2025-6204) KEV Surface & Version "
        "Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/delmia-apriso/version", 200,
        "\"delmia-apriso\"", "\"dassault-syst-mes\"",
        "tech/stack=delmia\\-apriso"
    },
    {
        "NVT-KEV-CVE-2025-6205",
        "Dassault Systèmes DELMIA Apriso (CVE-2025-6205) KEV Surface & Version "
        "Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/delmia-apriso/version", 200,
        "\"delmia-apriso\"", "\"dassault-syst-mes\"",
        "tech/stack=delmia\\-apriso"
    },
    {
        "NVT-KEV-CVE-2025-54236",
        "Adobe Commerce and Magento (CVE-2025-54236) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/commerce-and-magento/version", 200,
        "\"commerce-and-magento\"", "\"adobe\"",
        "tech/stack=commerce\\-and\\-magento"
    },
    {
        "NVT-KEV-CVE-2025-59287",
        "Microsoft Windows (CVE-2025-59287) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-502",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-61932",
        "Motex LANSCOPE Endpoint Manager (CVE-2025-61932) KEV Surface & Version"
        " Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/lanscope-endpoint-manager/version", 200,
        "\"lanscope-endpoint-manager\"", "\"motex\"",
        "tech/stack=lanscope\\-endpoint\\-manager"
    },
    {
        "NVT-KEV-CVE-2022-48503",
        "Apple Multiple Products (CVE-2022-48503) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"apple\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2025-2746",
        "Kentico Xperience CMS (CVE-2025-2746) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/xperience-cms/version", 200,
        "\"xperience-cms\"", "\"kentico\"",
        "tech/stack=xperience\\-cms"
    },
    {
        "NVT-KEV-CVE-2025-2747",
        "Kentico Xperience CMS (CVE-2025-2747) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/xperience-cms/version", 200,
        "\"xperience-cms\"", "\"kentico\"",
        "tech/stack=xperience\\-cms"
    },
    {
        "NVT-KEV-CVE-2025-33073",
        "Microsoft Windows (CVE-2025-33073) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-61884",
        "Oracle E-Business Suite (CVE-2025-61884) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-918",
        "/api/v1/e-business-suite/version", 200,
        "\"e-business-suite\"", "\"oracle\"",
        "tech/stack=e\\-business\\-suite"
    },
    {
        "NVT-KEV-CVE-2025-54253",
        "Adobe Experience Manager (AEM) Forms (CVE-2025-54253) KEV Surface & Ve"
        "rsion Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/experience-manager-aem-forms/version", 200,
        "\"experience-manager-aem-forms\"", "\"adobe\"",
        "tech/stack=experience\\-manager\\-aem\\-forms"
    },
    {
        "NVT-KEV-CVE-2025-47827",
        "IGEL IGEL OS (CVE-2025-47827) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/igel-os/version", 200,
        "\"igel-os\"", "\"igel\"",
        "tech/stack=igel\\-os"
    },
    {
        "NVT-KEV-CVE-2025-24990",
        "Microsoft Windows (CVE-2025-24990) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-59230",
        "Microsoft Windows (CVE-2025-59230) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2016-7836",
        "SKYSEA Client View (CVE-2016-7836) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/client-view/version", 200,
        "\"client-view\"", "\"skysea\"",
        "tech/stack=client\\-view"
    },
    {
        "NVT-KEV-CVE-2021-43798",
        "Grafana Labs Grafana (CVE-2021-43798) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/grafana/version", 200,
        "\"grafana\"", "\"grafana-labs\"",
        "tech/stack=grafana"
    },
    {
        "NVT-KEV-CVE-2025-27915",
        "Synacor Zimbra Collaboration Suite (ZCS) (CVE-2025-27915) KEV Surface "
        "& Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-79",
        "/api/v1/zimbra-collaboration-suite-zcs/version", 200,
        "\"zimbra-collaboration-suite-zcs\"", "\"synacor\"",
        "tech/stack=zimbra\\-collaboration\\-suite\\-zcs"
    },
    {
        "NVT-KEV-CVE-2021-22555",
        "Linux Kernel (CVE-2021-22555) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/kernel/version", 200,
        "\"kernel\"", "\"linux\"",
        "tech/stack=kernel"
    },
    {
        "NVT-KEV-CVE-2010-3962",
        "Microsoft Internet Explorer (CVE-2010-3962) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/internet-explorer/version", 200,
        "\"internet-explorer\"", "\"microsoft\"",
        "tech/stack=internet\\-explorer"
    },
    {
        "NVT-KEV-CVE-2021-43226",
        "Microsoft Windows (CVE-2021-43226) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2013-3918",
        "Microsoft Windows (CVE-2013-3918) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2011-3402",
        "Microsoft Windows (CVE-2011-3402) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2010-3765",
        "Mozilla Multiple Products (CVE-2010-3765) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"mozilla\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2025-61882",
        "Oracle E-Business Suite (CVE-2025-61882) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/e-business-suite/version", 200,
        "\"e-business-suite\"", "\"oracle\"",
        "tech/stack=e\\-business\\-suite"
    },
    {
        "NVT-KEV-CVE-2014-6278",
        "GNU GNU Bash (CVE-2014-6278) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/gnu-bash/version", 200,
        "\"gnu-bash\"", "\"gnu\"",
        "tech/stack=gnu\\-bash"
    },
    {
        "NVT-KEV-CVE-2017-1000353",
        "Jenkins Jenkins (CVE-2017-1000353) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/jenkins/version", 200,
        "\"jenkins\"", "\"jenkins\"",
        "tech/stack=jenkins"
    },
    {
        "NVT-KEV-CVE-2015-7755",
        "Juniper ScreenOS (CVE-2015-7755) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/screenos/version", 200,
        "\"screenos\"", "\"juniper\"",
        "tech/stack=screenos"
    },
    {
        "NVT-KEV-CVE-2025-21043",
        "Samsung Mobile Devices (CVE-2025-21043) KEV Surface & Version Metadata"
        " Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/mobile-devices/version", 200,
        "\"mobile-devices\"", "\"samsung\"",
        "tech/stack=mobile\\-devices"
    },
    {
        "NVT-KEV-CVE-2025-4008",
        "Smartbedded Meteobridge (CVE-2025-4008) KEV Surface & Version Metadata"
        " Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-306",
        "/api/v1/meteobridge/version", 200,
        "\"meteobridge\"", "\"smartbedded\"",
        "tech/stack=meteobridge"
    },
    {
        "NVT-KEV-CVE-2025-32463",
        "Sudo Sudo (CVE-2025-32463) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/sudo/version", 200,
        "\"sudo\"", "\"sudo\"",
        "tech/stack=sudo"
    },
    {
        "NVT-KEV-CVE-2025-59689",
        "Libraesva Email Security Gateway (CVE-2025-59689) KEV Surface & Versio"
        "n Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/email-security-gateway/version", 200,
        "\"email-security-gateway\"", "\"libraesva\"",
        "tech/stack=email\\-security\\-gateway"
    },
    {
        "NVT-KEV-CVE-2025-10035",
        "Fortra GoAnywhere MFT (CVE-2025-10035) KEV Surface & Version Metadata "
        "Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-502",
        "/api/v1/goanywhere-mft/version", 200,
        "\"goanywhere-mft\"", "\"fortra\"",
        "tech/stack=goanywhere\\-mft"
    },
    {
        "NVT-KEV-CVE-2025-20352",
        "Cisco IOS and IOS XE (CVE-2025-20352) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/ios-and-ios-xe/version", 200,
        "\"ios-and-ios-xe\"", "\"cisco\"",
        "tech/stack=ios\\-and\\-ios\\-xe"
    },
    {
        "NVT-KEV-CVE-2021-21311",
        "Adminer Adminer (CVE-2021-21311) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-918",
        "/api/v1/adminer/version", 200,
        "\"adminer\"", "\"adminer\"",
        "tech/stack=adminer"
    },
    {
        "NVT-KEV-CVE-2025-20362",
        "Cisco Secure Firewall Adaptive Security Appliance and Secure Firewall "
        "Threat Defense (CVE-2025-20362) KEV Surface & Version Metadata Exposur",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/secure-firewall-adaptive-security-ap/version", 200,
        "\"secure-firewall-adaptive-security-ap\"", "\"cisco\"",
        "tech/stack=secure\\-firewall\\-adaptive\\-security\\-ap"
    },
    {
        "NVT-KEV-CVE-2025-20333",
        "Cisco Secure Firewall Adaptive Security Appliance and Secure Firewall "
        "Threat Defense (CVE-2025-20333) KEV Surface & Version Metadata Exposur",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/secure-firewall-adaptive-security-ap/version", 200,
        "\"secure-firewall-adaptive-security-ap\"", "\"cisco\"",
        "tech/stack=secure\\-firewall\\-adaptive\\-security\\-ap"
    },
    {
        "NVT-KEV-CVE-2025-10585",
        "Google Chromium V8 (CVE-2025-10585) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/chromium-v8/version", 200,
        "\"chromium-v8\"", "\"google\"",
        "tech/stack=chromium\\-v8"
    },
    {
        "NVT-KEV-CVE-2025-5086",
        "Dassault Systèmes DELMIA Apriso (CVE-2025-5086) KEV Surface & Version "
        "Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-502",
        "/api/v1/delmia-apriso/version", 200,
        "\"delmia-apriso\"", "\"dassault-syst-mes\"",
        "tech/stack=delmia\\-apriso"
    },
    {
        "NVT-KEV-CVE-2025-38352",
        "Linux Kernel (CVE-2025-38352) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/kernel/version", 200,
        "\"kernel\"", "\"linux\"",
        "tech/stack=kernel"
    },
    {
        "NVT-KEV-CVE-2025-48543",
        "Android Runtime (CVE-2025-48543) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/runtime/version", 200,
        "\"runtime\"", "\"android\"",
        "tech/stack=runtime"
    },
    {
        "NVT-KEV-CVE-2025-53690",
        "Sitecore Multiple Products (CVE-2025-53690) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-502",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"sitecore\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2023-50224",
        "TP-Link TL-WR841N (CVE-2023-50224) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/tl-wr841n/version", 200,
        "\"tl-wr841n\"", "\"tp-link\"",
        "tech/stack=tl\\-wr841n"
    },
    {
        "NVT-KEV-CVE-2025-9377",
        "TP-Link Multiple Routers (CVE-2025-9377) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/multiple-routers/version", 200,
        "\"multiple-routers\"", "\"tp-link\"",
        "tech/stack=multiple\\-routers"
    },
    {
        "NVT-KEV-CVE-2020-24363",
        "TP-Link TL-WA855RE (CVE-2020-24363) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-306",
        "/api/v1/tl-wa855re/version", 200,
        "\"tl-wa855re\"", "\"tp-link\"",
        "tech/stack=tl\\-wa855re"
    },
    {
        "NVT-KEV-CVE-2025-55177",
        "Meta Platforms WhatsApp (CVE-2025-55177) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/whatsapp/version", 200,
        "\"whatsapp\"", "\"meta-platforms\"",
        "tech/stack=whatsapp"
    },
    {
        "NVT-KEV-CVE-2025-57819",
        "Sangoma FreePBX (CVE-2025-57819) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-89",
        "/api/v1/freepbx/version", 200,
        "\"freepbx\"", "\"sangoma\"",
        "tech/stack=freepbx"
    },
    {
        "NVT-KEV-CVE-2025-7775",
        "Citrix NetScaler (CVE-2025-7775) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/netscaler/version", 200,
        "\"netscaler\"", "\"citrix\"",
        "tech/stack=netscaler"
    },
    {
        "NVT-KEV-CVE-2025-48384",
        "Git Git (CVE-2025-48384) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/git/version", 200,
        "\"git\"", "\"git\"",
        "tech/stack=git"
    },
    {
        "NVT-KEV-CVE-2024-8068",
        "Citrix Session Recording (CVE-2024-8068) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/session-recording/version", 200,
        "\"session-recording\"", "\"citrix\"",
        "tech/stack=session\\-recording"
    },
    {
        "NVT-KEV-CVE-2024-8069",
        "Citrix Session Recording (CVE-2024-8069) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-502",
        "/api/v1/session-recording/version", 200,
        "\"session-recording\"", "\"citrix\"",
        "tech/stack=session\\-recording"
    },
    {
        "NVT-KEV-CVE-2025-43300",
        "Apple iOS, iPadOS, and macOS (CVE-2025-43300) KEV Surface & Version Me"
        "tadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/ios-ipados-and-macos/version", 200,
        "\"ios-ipados-and-macos\"", "\"apple\"",
        "tech/stack=ios\\-ipados\\-and\\-macos"
    },
    {
        "NVT-KEV-CVE-2025-54948",
        "Trend Micro Apex One (CVE-2025-54948) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/apex-one/version", 200,
        "\"apex-one\"", "\"trend-micro\"",
        "tech/stack=apex\\-one"
    },
    {
        "NVT-KEV-CVE-2025-8876",
        "N-able N-Central (CVE-2025-8876) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/n-central/version", 200,
        "\"n-central\"", "\"n-able\"",
        "tech/stack=n\\-central"
    },
    {
        "NVT-KEV-CVE-2025-8875",
        "N-able N-Central (CVE-2025-8875) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/n-central/version", 200,
        "\"n-central\"", "\"n-able\"",
        "tech/stack=n\\-central"
    },
    {
        "NVT-KEV-CVE-2025-8088",
        "RARLAB WinRAR (CVE-2025-8088) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/winrar/version", 200,
        "\"winrar\"", "\"rarlab\"",
        "tech/stack=winrar"
    },
    {
        "NVT-KEV-CVE-2007-0671",
        "Microsoft Office (CVE-2007-0671) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/office/version", 200,
        "\"office\"", "\"microsoft\"",
        "tech/stack=office"
    },
    {
        "NVT-KEV-CVE-2013-3893",
        "Microsoft Internet Explorer (CVE-2013-3893) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/internet-explorer/version", 200,
        "\"internet-explorer\"", "\"microsoft\"",
        "tech/stack=internet\\-explorer"
    },
    {
        "NVT-KEV-CVE-2020-25078",
        "D-Link DCS-2530L and DCS-2670L Devices (CVE-2020-25078) KEV Surface & "
        "Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/dcs-2530l-and-dcs-2670l-devices/version", 200,
        "\"dcs-2530l-and-dcs-2670l-devices\"", "\"d-link\"",
        "tech/stack=dcs\\-2530l\\-and\\-dcs\\-2670l\\-devices"
    },
    {
        "NVT-KEV-CVE-2020-25079",
        "D-Link DCS-2530L and DCS-2670L Devices (CVE-2020-25079) KEV Surface & "
        "Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/dcs-2530l-and-dcs-2670l-devices/version", 200,
        "\"dcs-2530l-and-dcs-2670l-devices\"", "\"d-link\"",
        "tech/stack=dcs\\-2530l\\-and\\-dcs\\-2670l\\-devices"
    },
    {
        "NVT-KEV-CVE-2022-40799",
        "D-Link DNR-322L (CVE-2022-40799) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/dnr-322l/version", 200,
        "\"dnr-322l\"", "\"d-link\"",
        "tech/stack=dnr\\-322l"
    },
    {
        "NVT-KEV-CVE-2023-2533",
        "PaperCut NG/MF (CVE-2023-2533) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/ng-mf/version", 200,
        "\"ng-mf\"", "\"papercut\"",
        "tech/stack=ng\\-mf"
    },
    {
        "NVT-KEV-CVE-2025-20337",
        "Cisco Identity Services Engine (CVE-2025-20337) KEV Surface & Version "
        "Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/identity-services-engine/version", 200,
        "\"identity-services-engine\"", "\"cisco\"",
        "tech/stack=identity\\-services\\-engine"
    },
    {
        "NVT-KEV-CVE-2025-20281",
        "Cisco Identity Services Engine (CVE-2025-20281) KEV Surface & Version "
        "Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/identity-services-engine/version", 200,
        "\"identity-services-engine\"", "\"cisco\"",
        "tech/stack=identity\\-services\\-engine"
    },
    {
        "NVT-KEV-CVE-2025-2775",
        "SysAid SysAid On-Prem (CVE-2025-2775) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/sysaid-on-prem/version", 200,
        "\"sysaid-on-prem\"", "\"sysaid\"",
        "tech/stack=sysaid\\-on\\-prem"
    },
    {
        "NVT-KEV-CVE-2025-2776",
        "SysAid SysAid On-Prem (CVE-2025-2776) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/sysaid-on-prem/version", 200,
        "\"sysaid-on-prem\"", "\"sysaid\"",
        "tech/stack=sysaid\\-on\\-prem"
    },
    {
        "NVT-KEV-CVE-2025-6558",
        "Google Chromium (CVE-2025-6558) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/chromium/version", 200,
        "\"chromium\"", "\"google\"",
        "tech/stack=chromium"
    },
    {
        "NVT-KEV-CVE-2025-54309",
        "CrushFTP CrushFTP (CVE-2025-54309) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/crushftp/version", 200,
        "\"crushftp\"", "\"crushftp\"",
        "tech/stack=crushftp"
    },
    {
        "NVT-KEV-CVE-2025-49704",
        "Microsoft SharePoint (CVE-2025-49704) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-94",
        "/api/v1/sharepoint/version", 200,
        "\"sharepoint\"", "\"microsoft\"",
        "tech/stack=sharepoint"
    },
    {
        "NVT-KEV-CVE-2025-49706",
        "Microsoft SharePoint (CVE-2025-49706) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-287",
        "/api/v1/sharepoint/version", 200,
        "\"sharepoint\"", "\"microsoft\"",
        "tech/stack=sharepoint"
    },
    {
        "NVT-KEV-CVE-2025-53770",
        "Microsoft SharePoint (CVE-2025-53770) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-502",
        "/api/v1/sharepoint/version", 200,
        "\"sharepoint\"", "\"microsoft\"",
        "tech/stack=sharepoint"
    },
    {
        "NVT-KEV-CVE-2025-25257",
        "Fortinet FortiWeb (CVE-2025-25257) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-89",
        "/api/v1/fortiweb/version", 200,
        "\"fortiweb\"", "\"fortinet\"",
        "tech/stack=fortiweb"
    },
    {
        "NVT-KEV-CVE-2025-47812",
        "Wing FTP Server Wing FTP Server (CVE-2025-47812) KEV Surface & Version"
        " Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/wing-ftp-server/version", 200,
        "\"wing-ftp-server\"", "\"wing-ftp-server\"",
        "tech/stack=wing\\-ftp\\-server"
    },
    {
        "NVT-KEV-CVE-2025-5777",
        "Citrix NetScaler ADC and Gateway (CVE-2025-5777) KEV Surface & Version"
        " Metadata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/netscaler-adc-and-gateway/version", 200,
        "\"netscaler-adc-and-gateway\"", "\"citrix\"",
        "tech/stack=netscaler\\-adc\\-and\\-gateway"
    },
    {
        "NVT-KEV-CVE-2019-9621",
        "Synacor Zimbra Collaboration Suite (ZCS) (CVE-2019-9621) KEV Surface &"
        " Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-918",
        "/api/v1/zimbra-collaboration-suite-zcs/version", 200,
        "\"zimbra-collaboration-suite-zcs\"", "\"synacor\"",
        "tech/stack=zimbra\\-collaboration\\-suite\\-zcs"
    },
    {
        "NVT-KEV-CVE-2019-5418",
        "Rails Ruby on Rails (CVE-2019-5418) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/ruby-on-rails/version", 200,
        "\"ruby-on-rails\"", "\"rails\"",
        "tech/stack=ruby\\-on\\-rails"
    },
    {
        "NVT-KEV-CVE-2016-10033",
        "PHP PHPMailer (CVE-2016-10033) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/phpmailer/version", 200,
        "\"phpmailer\"", "\"php\"",
        "tech/stack=phpmailer"
    },
    {
        "NVT-KEV-CVE-2014-3931",
        "Looking Glass Multi-Router Looking Glass (MRLG) (CVE-2014-3931) KEV Su"
        "rface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multi-router-looking-glass-mrlg/version", 200,
        "\"multi-router-looking-glass-mrlg\"", "\"looking-glass\"",
        "tech/stack=multi\\-router\\-looking\\-glass\\-mrlg"
    },
    {
        "NVT-KEV-CVE-2025-6554",
        "Google Chromium V8 (CVE-2025-6554) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/chromium-v8/version", 200,
        "\"chromium-v8\"", "\"google\"",
        "tech/stack=chromium\\-v8"
    },
    {
        "NVT-KEV-CVE-2025-48928",
        "TeleMessage TM SGNL (CVE-2025-48928) KEV Surface & Version Metadata Ex"
        "posure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/tm-sgnl/version", 200,
        "\"tm-sgnl\"", "\"telemessage\"",
        "tech/stack=tm\\-sgnl"
    },
    {
        "NVT-KEV-CVE-2025-48927",
        "TeleMessage TM SGNL (CVE-2025-48927) KEV Surface & Version Metadata Ex"
        "posure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/tm-sgnl/version", 200,
        "\"tm-sgnl\"", "\"telemessage\"",
        "tech/stack=tm\\-sgnl"
    },
    {
        "NVT-KEV-CVE-2025-6543",
        "Citrix NetScaler ADC and Gateway (CVE-2025-6543) KEV Surface & Version"
        " Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/netscaler-adc-and-gateway/version", 200,
        "\"netscaler-adc-and-gateway\"", "\"citrix\"",
        "tech/stack=netscaler\\-adc\\-and\\-gateway"
    },
    {
        "NVT-KEV-CVE-2019-6693",
        "Fortinet FortiOS (CVE-2019-6693) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-798",
        "/api/v1/fortios/version", 200,
        "\"fortios\"", "\"fortinet\"",
        "tech/stack=fortios"
    },
    {
        "NVT-KEV-CVE-2024-0769",
        "D-Link DIR-859 Router (CVE-2024-0769) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/dir-859-router/version", 200,
        "\"dir-859-router\"", "\"d-link\"",
        "tech/stack=dir\\-859\\-router"
    },
    {
        "NVT-KEV-CVE-2024-54085",
        "AMI MegaRAC SPx (CVE-2024-54085) KEV Surface & Version Metadata Exposu"
        "re",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/megarac-spx/version", 200,
        "\"megarac-spx\"", "\"ami\"",
        "tech/stack=megarac\\-spx"
    },
    {
        "NVT-KEV-CVE-2023-0386",
        "Linux Kernel (CVE-2023-0386) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/kernel/version", 200,
        "\"kernel\"", "\"linux\"",
        "tech/stack=kernel"
    },
    {
        "NVT-KEV-CVE-2023-33538",
        "TP-Link Multiple Routers (CVE-2023-33538) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/multiple-routers/version", 200,
        "\"multiple-routers\"", "\"tp-link\"",
        "tech/stack=multiple\\-routers"
    },
    {
        "NVT-KEV-CVE-2025-43200",
        "Apple Multiple Products (CVE-2025-43200) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"apple\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2025-33053",
        "Microsoft Windows (CVE-2025-33053) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-24016",
        "Wazuh Wazuh Server (CVE-2025-24016) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-502",
        "/api/v1/wazuh-server/version", 200,
        "\"wazuh-server\"", "\"wazuh\"",
        "tech/stack=wazuh\\-server"
    },
    {
        "NVT-KEV-CVE-2024-42009",
        "Roundcube Webmail (CVE-2024-42009) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-79",
        "/api/v1/webmail/version", 200,
        "\"webmail\"", "\"roundcube\"",
        "tech/stack=webmail"
    },
    {
        "NVT-KEV-CVE-2025-32433",
        "Erlang Erlang/OTP (CVE-2025-32433) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-306",
        "/api/v1/erlang-otp/version", 200,
        "\"erlang-otp\"", "\"erlang\"",
        "tech/stack=erlang\\-otp"
    },
    {
        "NVT-KEV-CVE-2025-5419",
        "Google Chromium V8 (CVE-2025-5419) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/chromium-v8/version", 200,
        "\"chromium-v8\"", "\"google\"",
        "tech/stack=chromium\\-v8"
    },
    {
        "NVT-KEV-CVE-2025-21479",
        "Qualcomm Multiple Chipsets (CVE-2025-21479) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/multiple-chipsets/version", 200,
        "\"multiple-chipsets\"", "\"qualcomm\"",
        "tech/stack=multiple\\-chipsets"
    },
    {
        "NVT-KEV-CVE-2025-21480",
        "Qualcomm Multiple Chipsets (CVE-2025-21480) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-284",
        "/api/v1/multiple-chipsets/version", 200,
        "\"multiple-chipsets\"", "\"qualcomm\"",
        "tech/stack=multiple\\-chipsets"
    },
    {
        "NVT-KEV-CVE-2025-27038",
        "Qualcomm Multiple Chipsets (CVE-2025-27038) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-chipsets/version", 200,
        "\"multiple-chipsets\"", "\"qualcomm\"",
        "tech/stack=multiple\\-chipsets"
    },
    {
        "NVT-KEV-CVE-2021-32030",
        "ASUS Routers (CVE-2021-32030) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/routers/version", 200,
        "\"routers\"", "\"asus\"",
        "tech/stack=routers"
    },
    {
        "NVT-KEV-CVE-2025-3935",
        "ConnectWise ScreenConnect (CVE-2025-3935) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/screenconnect/version", 200,
        "\"screenconnect\"", "\"connectwise\"",
        "tech/stack=screenconnect"
    },
    {
        "NVT-KEV-CVE-2025-35939",
        "Craft CMS Craft CMS (CVE-2025-35939) KEV Surface & Version Metadata Ex"
        "posure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/craft-cms/version", 200,
        "\"craft-cms\"", "\"craft-cms\"",
        "tech/stack=craft\\-cms"
    },
    {
        "NVT-KEV-CVE-2024-56145",
        "Craft CMS Craft CMS (CVE-2024-56145) KEV Surface & Version Metadata Ex"
        "posure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/craft-cms/version", 200,
        "\"craft-cms\"", "\"craft-cms\"",
        "tech/stack=craft\\-cms"
    },
    {
        "NVT-KEV-CVE-2023-39780",
        "ASUS RT-AX55 Routers (CVE-2023-39780) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/rt-ax55-routers/version", 200,
        "\"rt-ax55-routers\"", "\"asus\"",
        "tech/stack=rt\\-ax55\\-routers"
    },
    {
        "NVT-KEV-CVE-2025-4632",
        "Samsung MagicINFO 9 Server (CVE-2025-4632) KEV Surface & Version Metad"
        "ata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/magicinfo-9-server/version", 200,
        "\"magicinfo-9-server\"", "\"samsung\"",
        "tech/stack=magicinfo\\-9\\-server"
    },
    {
        "NVT-KEV-CVE-2023-38950",
        "ZKTeco BioTime (CVE-2023-38950) KEV Surface & Version Metadata Exposur"
        "e",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/biotime/version", 200,
        "\"biotime\"", "\"zkteco\"",
        "tech/stack=biotime"
    },
    {
        "NVT-KEV-CVE-2024-27443",
        "Synacor Zimbra Collaboration Suite (ZCS) (CVE-2024-27443) KEV Surface "
        "& Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-79",
        "/api/v1/zimbra-collaboration-suite-zcs/version", 200,
        "\"zimbra-collaboration-suite-zcs\"", "\"synacor\"",
        "tech/stack=zimbra\\-collaboration\\-suite\\-zcs"
    },
    {
        "NVT-KEV-CVE-2025-27920",
        "Srimax Output Messenger (CVE-2025-27920) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/output-messenger/version", 200,
        "\"output-messenger\"", "\"srimax\"",
        "tech/stack=output\\-messenger"
    },
    {
        "NVT-KEV-CVE-2024-11182",
        "MDaemon Email Server (CVE-2024-11182) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-79",
        "/api/v1/email-server/version", 200,
        "\"email-server\"", "\"mdaemon\"",
        "tech/stack=email\\-server"
    },
    {
        "NVT-KEV-CVE-2025-4428",
        "Ivanti Endpoint Manager Mobile (EPMM) (CVE-2025-4428) KEV Surface & Ve"
        "rsion Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/endpoint-manager-mobile-epmm/version", 200,
        "\"endpoint-manager-mobile-epmm\"", "\"ivanti\"",
        "tech/stack=endpoint\\-manager\\-mobile\\-epmm"
    },
    {
        "NVT-KEV-CVE-2025-4427",
        "Ivanti Endpoint Manager Mobile (EPMM) (CVE-2025-4427) KEV Surface & Ve"
        "rsion Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-287",
        "/api/v1/endpoint-manager-mobile-epmm/version", 200,
        "\"endpoint-manager-mobile-epmm\"", "\"ivanti\"",
        "tech/stack=endpoint\\-manager\\-mobile\\-epmm"
    },
    {
        "NVT-KEV-CVE-2025-42999",
        "SAP NetWeaver (CVE-2025-42999) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-502",
        "/api/v1/netweaver/version", 200,
        "\"netweaver\"", "\"sap\"",
        "tech/stack=netweaver"
    },
    {
        "NVT-KEV-CVE-2024-12987",
        "DrayTek Vigor Routers (CVE-2024-12987) KEV Surface & Version Metadata "
        "Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/vigor-routers/version", 200,
        "\"vigor-routers\"", "\"draytek\"",
        "tech/stack=vigor\\-routers"
    },
    {
        "NVT-KEV-CVE-2025-32756",
        "Fortinet Multiple Products (CVE-2025-32756) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"fortinet\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2025-32709",
        "Microsoft Windows (CVE-2025-32709) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-30397",
        "Microsoft Windows (CVE-2025-30397) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-32706",
        "Microsoft Windows (CVE-2025-32706) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-32701",
        "Microsoft Windows (CVE-2025-32701) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-30400",
        "Microsoft Windows (CVE-2025-30400) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-47729",
        "TeleMessage TM SGNL (CVE-2025-47729) KEV Surface & Version Metadata Ex"
        "posure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/tm-sgnl/version", 200,
        "\"tm-sgnl\"", "\"telemessage\"",
        "tech/stack=tm\\-sgnl"
    },
    {
        "NVT-KEV-CVE-2024-11120",
        "GeoVision Multiple Devices (CVE-2024-11120) KEV Surface & Version Meta"
        "data Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/multiple-devices/version", 200,
        "\"multiple-devices\"", "\"geovision\"",
        "tech/stack=multiple\\-devices"
    },
    {
        "NVT-KEV-CVE-2024-6047",
        "GeoVision Multiple Devices (CVE-2024-6047) KEV Surface & Version Metad"
        "ata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/multiple-devices/version", 200,
        "\"multiple-devices\"", "\"geovision\"",
        "tech/stack=multiple\\-devices"
    },
    {
        "NVT-KEV-CVE-2025-27363",
        "FreeType FreeType (CVE-2025-27363) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/freetype/version", 200,
        "\"freetype\"", "\"freetype\"",
        "tech/stack=freetype"
    },
    {
        "NVT-KEV-CVE-2025-3248",
        "Langflow Langflow (CVE-2025-3248) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-306",
        "/api/v1/langflow/version", 200,
        "\"langflow\"", "\"langflow\"",
        "tech/stack=langflow"
    },
    {
        "NVT-KEV-CVE-2025-34028",
        "Commvault Command Center (CVE-2025-34028) KEV Surface & Version Metada"
        "ta Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/command-center/version", 200,
        "\"command-center\"", "\"commvault\"",
        "tech/stack=command\\-center"
    },
    {
        "NVT-KEV-CVE-2024-58136",
        "Yiiframework Yii (CVE-2024-58136) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/yii/version", 200,
        "\"yii\"", "\"yiiframework\"",
        "tech/stack=yii"
    },
    {
        "NVT-KEV-CVE-2024-38475",
        "Apache HTTP Server (CVE-2024-38475) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/http-server/version", 200,
        "\"http-server\"", "\"apache\"",
        "tech/stack=http\\-server"
    },
    {
        "NVT-KEV-CVE-2023-44221",
        "SonicWall SMA100 Appliances (CVE-2023-44221) KEV Surface & Version Met"
        "adata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/sma100-appliances/version", 200,
        "\"sma100-appliances\"", "\"sonicwall\"",
        "tech/stack=sma100\\-appliances"
    },
    {
        "NVT-KEV-CVE-2025-31324",
        "SAP NetWeaver (CVE-2025-31324) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/netweaver/version", 200,
        "\"netweaver\"", "\"sap\"",
        "tech/stack=netweaver"
    },
    {
        "NVT-KEV-CVE-2025-1976",
        "Broadcom Brocade Fabric OS (CVE-2025-1976) KEV Surface & Version Metad"
        "ata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-94",
        "/api/v1/brocade-fabric-os/version", 200,
        "\"brocade-fabric-os\"", "\"broadcom\"",
        "tech/stack=brocade\\-fabric\\-os"
    },
    {
        "NVT-KEV-CVE-2025-42599",
        "Qualitia Active! Mail (CVE-2025-42599) KEV Surface & Version Metadata "
        "Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/active-mail/version", 200,
        "\"active-mail\"", "\"qualitia\"",
        "tech/stack=active\\-mail"
    },
    {
        "NVT-KEV-CVE-2025-3928",
        "Commvault Web Server (CVE-2025-3928) KEV Surface & Version Metadata Ex"
        "posure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/web-server/version", 200,
        "\"web-server\"", "\"commvault\"",
        "tech/stack=web\\-server"
    },
    {
        "NVT-KEV-CVE-2025-24054",
        "Microsoft Windows (CVE-2025-24054) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-31201",
        "Apple Multiple Products (CVE-2025-31201) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"apple\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2025-31200",
        "Apple Multiple Products (CVE-2025-31200) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"apple\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2021-20035",
        "SonicWall SMA100 Appliances (CVE-2021-20035) KEV Surface & Version Met"
        "adata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/sma100-appliances/version", 200,
        "\"sma100-appliances\"", "\"sonicwall\"",
        "tech/stack=sma100\\-appliances"
    },
    {
        "NVT-KEV-CVE-2024-53150",
        "Linux Kernel (CVE-2024-53150) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/kernel/version", 200,
        "\"kernel\"", "\"linux\"",
        "tech/stack=kernel"
    },
    {
        "NVT-KEV-CVE-2024-53197",
        "Linux Kernel (CVE-2024-53197) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/kernel/version", 200,
        "\"kernel\"", "\"linux\"",
        "tech/stack=kernel"
    },
    {
        "NVT-KEV-CVE-2025-29824",
        "Microsoft Windows (CVE-2025-29824) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-30406",
        "Gladinet CentreStack (CVE-2025-30406) KEV Surface & Version Metadata E"
        "xposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/centrestack/version", 200,
        "\"centrestack\"", "\"gladinet\"",
        "tech/stack=centrestack"
    },
    {
        "NVT-KEV-CVE-2025-31161",
        "CrushFTP CrushFTP (CVE-2025-31161) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/crushftp/version", 200,
        "\"crushftp\"", "\"crushftp\"",
        "tech/stack=crushftp"
    },
    {
        "NVT-KEV-CVE-2025-22457",
        "Ivanti Connect Secure, Policy Secure, and ZTA Gateways (CVE-2025-22457"
        ") KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/connect-secure-policy-secure-and-zta/version", 200,
        "\"connect-secure-policy-secure-and-zta\"", "\"ivanti\"",
        "tech/stack=connect\\-secure\\-policy\\-secure\\-and\\-zta"
    },
    {
        "NVT-KEV-CVE-2025-24813",
        "Apache Tomcat (CVE-2025-24813) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-502",
        "/api/v1/tomcat/version", 200,
        "\"tomcat\"", "\"apache\"",
        "tech/stack=tomcat"
    },
    {
        "NVT-KEV-CVE-2024-20439",
        "Cisco Smart Licensing Utility (CVE-2024-20439) KEV Surface & Version M"
        "etadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/smart-licensing-utility/version", 200,
        "\"smart-licensing-utility\"", "\"cisco\"",
        "tech/stack=smart\\-licensing\\-utility"
    },
    {
        "NVT-KEV-CVE-2025-2783",
        "Google Chromium Mojo (CVE-2025-2783) KEV Surface & Version Metadata Ex"
        "posure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/chromium-mojo/version", 200,
        "\"chromium-mojo\"", "\"google\"",
        "tech/stack=chromium\\-mojo"
    },
    {
        "NVT-KEV-CVE-2019-9875",
        "Sitecore CMS and Experience Platform (XP) (CVE-2019-9875) KEV Surface "
        "& Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-502",
        "/api/v1/cms-and-experience-platform-xp/version", 200,
        "\"cms-and-experience-platform-xp\"", "\"sitecore\"",
        "tech/stack=cms\\-and\\-experience\\-platform\\-xp"
    },
    {
        "NVT-KEV-CVE-2019-9874",
        "Sitecore CMS and Experience Platform (XP) (CVE-2019-9874) KEV Surface "
        "& Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-502",
        "/api/v1/cms-and-experience-platform-xp/version", 200,
        "\"cms-and-experience-platform-xp\"", "\"sitecore\"",
        "tech/stack=cms\\-and\\-experience\\-platform\\-xp"
    },
    {
        "NVT-KEV-CVE-2025-30154",
        "reviewdog action-setup GitHub Action (CVE-2025-30154) KEV Surface & Ve"
        "rsion Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/action-setup-github-action/version", 200,
        "\"action-setup-github-action\"", "\"reviewdog\"",
        "tech/stack=action\\-setup\\-github\\-action"
    },
    {
        "NVT-KEV-CVE-2017-12637",
        "SAP NetWeaver (CVE-2017-12637) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-22",
        "/api/v1/netweaver/version", 200,
        "\"netweaver\"", "\"sap\"",
        "tech/stack=netweaver"
    },
    {
        "NVT-KEV-CVE-2024-48248",
        "NAKIVO Backup and Replication (CVE-2024-48248) KEV Surface & Version M"
        "etadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/backup-and-replication/version", 200,
        "\"backup-and-replication\"", "\"nakivo\"",
        "tech/stack=backup\\-and\\-replication"
    },
    {
        "NVT-KEV-CVE-2025-1316",
        "Edimax IC-7100 IP Camera (CVE-2025-1316) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-78",
        "/api/v1/ic-7100-ip-camera/version", 200,
        "\"ic-7100-ip-camera\"", "\"edimax\"",
        "tech/stack=ic\\-7100\\-ip\\-camera"
    },
    {
        "NVT-KEV-CVE-2025-30066",
        "tj-actions changed-files GitHub Action (CVE-2025-30066) KEV Surface & "
        "Version Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/changed-files-github-action/version", 200,
        "\"changed-files-github-action\"", "\"tj-actions\"",
        "tech/stack=changed\\-files\\-github\\-action"
    },
    {
        "NVT-KEV-CVE-2025-24472",
        "Fortinet FortiOS and FortiProxy (CVE-2025-24472) KEV Surface & Version"
        " Metadata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-287",
        "/api/v1/fortios-and-fortiproxy/version", 200,
        "\"fortios-and-fortiproxy\"", "\"fortinet\"",
        "tech/stack=fortios\\-and\\-fortiproxy"
    },
    {
        "NVT-KEV-CVE-2025-21590",
        "Juniper Junos OS (CVE-2025-21590) KEV Surface & Version Metadata Expos"
        "ure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/junos-os/version", 200,
        "\"junos-os\"", "\"juniper\"",
        "tech/stack=junos\\-os"
    },
    {
        "NVT-KEV-CVE-2025-24201",
        "Apple Multiple Products (CVE-2025-24201) KEV Surface & Version Metadat"
        "a Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/multiple-products/version", 200,
        "\"multiple-products\"", "\"apple\"",
        "tech/stack=multiple\\-products"
    },
    {
        "NVT-KEV-CVE-2025-24993",
        "Microsoft Windows (CVE-2025-24993) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-24991",
        "Microsoft Windows (CVE-2025-24991) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-24985",
        "Microsoft Windows (CVE-2025-24985) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-24984",
        "Microsoft Windows (CVE-2025-24984) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-24983",
        "Microsoft Windows (CVE-2025-24983) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2025-26633",
        "Microsoft Windows (CVE-2025-26633) KEV Surface & Version Metadata Expo"
        "sure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/windows/version", 200,
        "\"windows\"", "\"microsoft\"",
        "tech/stack=windows"
    },
    {
        "NVT-KEV-CVE-2024-13161",
        "Ivanti Endpoint Manager (EPM) (CVE-2024-13161) KEV Surface & Version M"
        "etadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/endpoint-manager-epm/version", 200,
        "\"endpoint-manager-epm\"", "\"ivanti\"",
        "tech/stack=endpoint\\-manager\\-epm"
    },
    {
        "NVT-KEV-CVE-2024-13160",
        "Ivanti Endpoint Manager (EPM) (CVE-2024-13160) KEV Surface & Version M"
        "etadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/endpoint-manager-epm/version", 200,
        "\"endpoint-manager-epm\"", "\"ivanti\"",
        "tech/stack=endpoint\\-manager\\-epm"
    },
    {
        "NVT-KEV-CVE-2024-13159",
        "Ivanti Endpoint Manager (EPM) (CVE-2024-13159) KEV Surface & Version M"
        "etadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/endpoint-manager-epm/version", 200,
        "\"endpoint-manager-epm\"", "\"ivanti\"",
        "tech/stack=endpoint\\-manager\\-epm"
    },
    {
        "NVT-KEV-CVE-2024-57968",
        "Advantive VeraCore (CVE-2024-57968) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/veracore/version", 200,
        "\"veracore\"", "\"advantive\"",
        "tech/stack=veracore"
    },
    {
        "NVT-KEV-CVE-2025-25181",
        "Advantive VeraCore (CVE-2025-25181) KEV Surface & Version Metadata Exp"
        "osure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-89",
        "/api/v1/veracore/version", 200,
        "\"veracore\"", "\"advantive\"",
        "tech/stack=veracore"
    },
    {
        "NVT-KEV-CVE-2025-22226",
        "VMware ESXi, Workstation, and Fusion (CVE-2025-22226) KEV Surface & Ve"
        "rsion Metadata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/esxi-workstation-and-fusion/version", 200,
        "\"esxi-workstation-and-fusion\"", "\"vmware\"",
        "tech/stack=esxi\\-workstation\\-and\\-fusion"
    },
    {
        "NVT-KEV-CVE-2025-22225",
        "VMware ESXi (CVE-2025-22225) KEV Surface & Version Metadata Exposure",
        "CISA KEV Exposure Posture", "Critical", 98, "CWE-1104",
        "/api/v1/esxi/version", 200,
        "\"esxi\"", "\"vmware\"",
        "tech/stack=esxi"
    },
    {
        "NVT-KEV-CVE-2025-22224",
        "VMware ESXi and Workstation (CVE-2025-22224) KEV Surface & Version Met"
        "adata Exposure",
        "CISA KEV Exposure Posture", "High", 88, "CWE-1104",
        "/api/v1/esxi-and-workstation/version", 200,
        "\"esxi-and-workstation\"", "\"vmware\"",
        "tech/stack=esxi\\-and\\-workstation"
    },
};
} // namespace
extern "C" {
uint32_t spectre_cpp_nvt_rodata_count() {
    const auto c1 = static_cast<uint32_t>(sizeof(kNativeNvtPart1) / sizeof(kNativeNvtPart1[0]));
    return c1 + spectre_rodata::nvt_part2_count();
}
int spectre_cpp_lookup_favicon_mmh3(int32_t hash_val, char* out_buf, size_t out_cap) {
    if (!out_buf || out_cap < 2) return 0;
    out_buf[0] = '\0';
    const size_t n = sizeof(kFaviconTable) / sizeof(kFaviconTable[0]);
    auto it = std::lower_bound(kFaviconTable, kFaviconTable + n, hash_val,
        [](const FaviconSpec& a, int32_t v) { return a.mmh3 < v; });
    if (it != kFaviconTable + n && it->mmh3 == hash_val) {
        std::strncpy(out_buf, it->product, out_cap - 1);
        out_buf[out_cap - 1] = '\0';
        return 1;
    }
    return 0;
}
} // extern C
