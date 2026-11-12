"""
SPECTRE v13.0 — Clean Domain-Driven Capability Facade
=====================================================
Consolidates historically versioned modules (v5, deep, ultra, predator,
v10, v11, v12) into 6 clean domain namespaces without breaking legacy imports.
"""

from __future__ import annotations

from agents import (
    spectre_deep_modules,
    spectre_predator_modules,
    spectre_ultra_modules,
    spectre_v5_modules,
    spectre_v10_modules,
    spectre_v11_modules,
    spectre_v12_modules,
)


class DnsIntelDomain:
    run_subdomain_cli_mesh = staticmethod(spectre_v5_modules.run_deep_subdomain_tools)
    audit_spf_dmarc = staticmethod(spectre_v10_modules.validate_spf_dmarc_recursive)
    discover_sister_domains = staticmethod(spectre_v11_modules.discover_related_sister_domains)


class NetworkSurfaceDomain:
    enrich_asn_intel = staticmethod(spectre_v5_modules.enrich_asn_and_isp_intel)
    run_port_and_nse_scan = staticmethod(spectre_v5_modules.run_deep_network_and_ad_tools)
    audit_tls_certificates = staticmethod(spectre_v5_modules.audit_ssl_certificates_deep)
    map_subnet_ptr_neighbors = staticmethod(spectre_ultra_modules.sweep_subnet_neighbors_and_ptr)
    probe_custom_web_ports = staticmethod(spectre_deep_modules.probe_nonstandard_web_ports)
    hunt_virtual_hosts = staticmethod(spectre_deep_modules.hunt_virtual_hosts)
    probe_ipv6_dual_stack = staticmethod(spectre_v12_modules.resolve_and_probe_ipv6_dual_stack)
    probe_udp_services = staticmethod(spectre_v12_modules.probe_udp_services_safe)


class WebSurfaceDomain:
    run_web_crawlers_and_fuzzers = staticmethod(spectre_v5_modules.run_deep_web_and_fuzz_tools)
    fingerprint_favicon = staticmethod(spectre_predator_modules.fingerprint_favicon_hash_and_tech)
    audit_reverse_proxy_acls = staticmethod(spectre_predator_modules.audit_reverse_proxy_acl_misconfigs)
    audit_vcs_exposure = staticmethod(spectre_v10_modules.audit_vcs_metadata_exposure)
    audit_cache_headers = staticmethod(spectre_v10_modules.audit_cache_policy_and_headers)
    cluster_dom_templates = staticmethod(spectre_v11_modules.cluster_subdomains_by_dom_structure)
    audit_csp_nonces = staticmethod(spectre_v12_modules.audit_csp_deep_and_static_nonce)


class ApiSchemaDomain:
    mine_hidden_params = staticmethod(spectre_predator_modules.mine_hidden_query_parameters)
    introspect_graphql = staticmethod(spectre_predator_modules.introspect_graphql_field_suggestions)
    extract_grpc_schemas = staticmethod(spectre_v10_modules.extract_grpc_and_protobuf_schemas)
    map_oidc_keycloak_realms = staticmethod(spectre_v11_modules.map_iam_and_keycloak_realms)
    synthesize_openapi_dtos = staticmethod(spectre_v11_modules.resolve_openapi_schema_refs)
    harvest_cors_preflight = staticmethod(spectre_v11_modules.harvest_cors_preflight_capabilities)
    predict_semantic_rest = staticmethod(spectre_v12_modules.predict_and_verify_semantic_rest_endpoints)
    probe_shadow_api_versions = staticmethod(spectre_deep_modules.probe_api_versions_and_ghost_endpoints)


class JsDeconstructorDomain:
    unpack_sourcemaps = staticmethod(spectre_predator_modules.unpack_js_sourcemaps)
    check_dependency_confusion = staticmethod(spectre_predator_modules.hunt_dependency_confusion_risks)
    audit_jwt_tokens = staticmethod(spectre_predator_modules.harvest_and_audit_jwt_tokens)
    analyze_postmessage = staticmethod(spectre_v10_modules.analyze_postmessage_handlers)
    predict_webpack_chunks = staticmethod(spectre_v11_modules.predict_and_fetch_webpack_chunks)
    render_headless_v8_dom = staticmethod(spectre_v12_modules.headless_chrome_dom_and_route_renderer)
    analyze_wasm_binaries = staticmethod(spectre_v12_modules.analyze_wasm_binaries_and_server_timing)


class CloudOsintDomain:
    enumerate_multicloud_containers = staticmethod(spectre_predator_modules.enumerate_multicloud_and_containers)
    hunt_secrets_and_fintech = staticmethod(spectre_ultra_modules.hunt_deep_secrets_and_uz_ecosystem)
    extract_doc_metadata = staticmethod(spectre_ultra_modules.extract_document_metadata_osint)
    correlate_backend_topology = staticmethod(spectre_v12_modules.build_corporate_org_and_backend_correlation_graph)
