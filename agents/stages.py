"""
SPECTRE v12.3 — Modular Stage Registry & Clean Architecture Index
=================================================================
Organizes all 1-SuperAgent reconnaissance engines into 6 logical stages
so every module is discoverable, typed, and verifiable in <100 lines.
"""

from __future__ import annotations

from agents import (
    spectre_deep_modules,
    spectre_v5_modules,
    spectre_ultra_modules,
    spectre_predator_modules,
    spectre_v10_modules,
    spectre_v11_modules,
    spectre_v12_modules,
)

STAGE1_DNS_ENGINES = (
    spectre_v5_modules.run_deep_subdomain_tools,
    spectre_v10_modules.validate_spf_dmarc_recursive,
    spectre_v11_modules.discover_related_sister_domains,
)

STAGE2_NETWORK_ENGINES = (
    spectre_v5_modules.enrich_asn_and_isp_intel,
    spectre_v5_modules.run_deep_network_and_ad_tools,
    spectre_v5_modules.audit_ssl_certificates_deep,
    spectre_ultra_modules.sweep_subnet_neighbors_and_ptr,
    spectre_ultra_modules.unmask_cloudflare_origin_ips,
    spectre_deep_modules.probe_nonstandard_web_ports,
    spectre_deep_modules.hunt_virtual_hosts,
    spectre_v12_modules.resolve_and_probe_ipv6_dual_stack,
    spectre_v12_modules.probe_udp_services_safe,
)

STAGE3_WEB_SURFACE_ENGINES = (
    spectre_predator_modules.fingerprint_favicon_hash_and_tech,
    spectre_predator_modules.audit_reverse_proxy_acl_misconfigs,
    spectre_v10_modules.audit_vcs_metadata_exposure,
    spectre_v10_modules.audit_static_routing_headers,
    spectre_v10_modules.audit_cache_policy_and_headers,
    spectre_v10_modules.inspect_http_protocol_and_proxy_topology,
    spectre_v10_modules.verify_archive_magic_bytes_range,
    spectre_v11_modules.fingerprint_load_balancer_and_etag,
    spectre_v11_modules.cluster_subdomains_by_dom_structure,
    spectre_v12_modules.audit_csp_deep_and_static_nonce,
)

STAGE4_API_SCHEMA_ENGINES = (
    spectre_predator_modules.mine_hidden_query_parameters,
    spectre_predator_modules.audit_websocket_endpoints_and_cswsh,
    spectre_predator_modules.introspect_graphql_field_suggestions,
    spectre_v10_modules.extract_grpc_and_protobuf_schemas,
    spectre_v10_modules.audit_oauth_oidc_parameters,
    spectre_v11_modules.map_iam_and_keycloak_realms,
    spectre_v11_modules.resolve_openapi_schema_refs,
    spectre_v11_modules.harvest_cors_preflight_capabilities,
    spectre_v12_modules.predict_and_verify_semantic_rest_endpoints,
    spectre_deep_modules.probe_api_versions_and_ghost_endpoints,
)

STAGE5_JS_AND_CLIENT_ENGINES = (
    spectre_predator_modules.unpack_js_sourcemaps,
    spectre_predator_modules.hunt_dependency_confusion_risks,
    spectre_predator_modules.harvest_and_audit_jwt_tokens,
    spectre_predator_modules.hunt_broken_external_links_and_script_hijack,
    spectre_v10_modules.analyze_postmessage_handlers,
    spectre_v10_modules.parse_service_worker_manifests,
    spectre_v10_modules.extract_client_storage_keys_and_checks,
    spectre_v11_modules.predict_and_fetch_webpack_chunks,
    spectre_v11_modules.mine_i18n_translation_dictionaries,
    spectre_v12_modules.headless_chrome_dom_and_route_renderer,
    spectre_v12_modules.analyze_wasm_binaries_and_server_timing,
)

STAGE6_CLOUD_AND_CORRELATION_ENGINES = (
    spectre_ultra_modules.run_adaptive_brain_strategy,
    spectre_ultra_modules.deconstruct_spa_manifests_and_ssr_state,
    spectre_ultra_modules.hunt_deep_secrets_and_uz_ecosystem,
    spectre_ultra_modules.mine_well_known_and_mobile_links,
    spectre_ultra_modules.trace_redirect_chains_and_oauth_flows,
    spectre_ultra_modules.run_safe_auto_validator,
    spectre_ultra_modules.extract_document_metadata_osint,
    spectre_predator_modules.enumerate_multicloud_and_containers,
    spectre_v10_modules.correlate_analytics_and_tag_ids,
    spectre_v12_modules.build_corporate_org_and_backend_correlation_graph,
)
