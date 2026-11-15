"""
SPECTRE v3.0 — Domain-Driven Capability Facade
==============================================
Organizes reconnaissance and audit capabilities into 6 clean domain namespaces.
"""

from __future__ import annotations

from agents import (
    active_web_auditor,
    cli_orchestrator,
    origin_and_spa,
    protocol_and_client,
    runtime_and_network,
    schema_and_iam,
    surface_prober,
)


class DnsIntelDomain:
    run_subdomain_cli_mesh = staticmethod(cli_orchestrator.run_deep_subdomain_tools)
    audit_spf_dmarc = staticmethod(protocol_and_client.validate_spf_dmarc_recursive)
    discover_sister_domains = staticmethod(schema_and_iam.discover_related_sister_domains)


class NetworkSurfaceDomain:
    enrich_asn_intel = staticmethod(cli_orchestrator.enrich_asn_and_isp_intel)
    run_port_and_nse_scan = staticmethod(cli_orchestrator.run_deep_network_and_ad_tools)
    audit_tls_certificates = staticmethod(cli_orchestrator.audit_ssl_certificates_deep)
    map_subnet_ptr_neighbors = staticmethod(origin_and_spa.sweep_subnet_neighbors_and_ptr)
    probe_custom_web_ports = staticmethod(surface_prober.probe_nonstandard_web_ports)
    hunt_virtual_hosts = staticmethod(surface_prober.hunt_virtual_hosts)
    probe_ipv6_dual_stack = staticmethod(runtime_and_network.resolve_and_probe_ipv6_dual_stack)
    probe_udp_services = staticmethod(runtime_and_network.probe_udp_services_safe)


class WebSurfaceDomain:
    run_web_crawlers_and_fuzzers = staticmethod(cli_orchestrator.run_deep_web_and_fuzz_tools)
    fingerprint_favicon = staticmethod(active_web_auditor.fingerprint_favicon_hash_and_tech)
    audit_reverse_proxy_acls = staticmethod(active_web_auditor.audit_reverse_proxy_acl_misconfigs)
    audit_vcs_exposure = staticmethod(protocol_and_client.audit_vcs_metadata_exposure)
    audit_cache_headers = staticmethod(protocol_and_client.audit_cache_policy_and_headers)
    cluster_dom_templates = staticmethod(schema_and_iam.cluster_subdomains_by_dom_structure)
    audit_csp_nonces = staticmethod(runtime_and_network.audit_csp_deep_and_static_nonce)


class ApiSchemaDomain:
    mine_hidden_params = staticmethod(active_web_auditor.mine_hidden_query_parameters)
    introspect_graphql = staticmethod(active_web_auditor.introspect_graphql_field_suggestions)
    extract_grpc_schemas = staticmethod(protocol_and_client.extract_grpc_and_protobuf_schemas)
    map_oidc_keycloak_realms = staticmethod(schema_and_iam.map_iam_and_keycloak_realms)
    synthesize_openapi_dtos = staticmethod(schema_and_iam.resolve_openapi_schema_refs)
    harvest_cors_preflight = staticmethod(schema_and_iam.harvest_cors_preflight_capabilities)
    predict_semantic_rest = staticmethod(runtime_and_network.predict_and_verify_semantic_rest_endpoints)
    probe_shadow_api_versions = staticmethod(surface_prober.probe_api_versions_and_ghost_endpoints)


class JsDeconstructorDomain:
    unpack_sourcemaps = staticmethod(active_web_auditor.unpack_js_sourcemaps)
    check_dependency_confusion = staticmethod(active_web_auditor.hunt_dependency_confusion_risks)
    audit_jwt_tokens = staticmethod(active_web_auditor.harvest_and_audit_jwt_tokens)
    analyze_postmessage = staticmethod(protocol_and_client.analyze_postmessage_handlers)
    predict_webpack_chunks = staticmethod(schema_and_iam.predict_and_fetch_webpack_chunks)
    render_headless_v8_dom = staticmethod(runtime_and_network.headless_chrome_dom_and_route_renderer)
    analyze_wasm_binaries = staticmethod(runtime_and_network.analyze_wasm_binaries_and_server_timing)


class CloudOsintDomain:
    enumerate_multicloud_containers = staticmethod(active_web_auditor.enumerate_multicloud_and_containers)
    hunt_secrets_and_fintech = staticmethod(origin_and_spa.hunt_deep_secrets_and_uz_ecosystem)
    extract_doc_metadata = staticmethod(origin_and_spa.extract_document_metadata_osint)
    correlate_backend_topology = staticmethod(runtime_and_network.build_corporate_org_and_backend_correlation_graph)

