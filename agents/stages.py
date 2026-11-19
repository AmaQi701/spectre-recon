"""
SPECTRE v3.0 — Modular Stage Registry & Clean Architecture Index
================================================================
Organizes all 1-SuperAgent reconnaissance engines into 6 logical stages
so every module is discoverable, typed, and verifiable in <100 lines.
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

STAGE1_DNS_ENGINES = (
    cli_orchestrator.run_deep_subdomain_tools,
    protocol_and_client.validate_spf_dmarc_recursive,
    schema_and_iam.discover_related_sister_domains,
)

STAGE2_NETWORK_ENGINES = (
    cli_orchestrator.enrich_asn_and_isp_intel,
    cli_orchestrator.run_deep_network_and_ad_tools,
    cli_orchestrator.audit_ssl_certificates_deep,
    origin_and_spa.sweep_subnet_neighbors_and_ptr,
    origin_and_spa.unmask_cloudflare_origin_ips,
    surface_prober.probe_nonstandard_web_ports,
    surface_prober.hunt_virtual_hosts,
    runtime_and_network.resolve_and_probe_ipv6_dual_stack,
    runtime_and_network.probe_udp_services_safe,
)

STAGE3_WEB_SURFACE_ENGINES = (
    active_web_auditor.fingerprint_favicon_hash_and_tech,
    active_web_auditor.audit_reverse_proxy_acl_misconfigs,
    protocol_and_client.audit_vcs_metadata_exposure,
    protocol_and_client.audit_static_routing_headers,
    protocol_and_client.audit_cache_policy_and_headers,
    protocol_and_client.inspect_http_protocol_and_proxy_topology,
    protocol_and_client.verify_archive_magic_bytes_range,
    schema_and_iam.fingerprint_load_balancer_and_etag,
    schema_and_iam.cluster_subdomains_by_dom_structure,
    runtime_and_network.audit_csp_deep_and_static_nonce,
)

STAGE4_API_SCHEMA_ENGINES = (
    active_web_auditor.mine_hidden_query_parameters,
    active_web_auditor.audit_websocket_endpoints_and_cswsh,
    active_web_auditor.introspect_graphql_field_suggestions,
    protocol_and_client.extract_grpc_and_protobuf_schemas,
    protocol_and_client.audit_oauth_oidc_parameters,
    schema_and_iam.map_iam_and_keycloak_realms,
    schema_and_iam.resolve_openapi_schema_refs,
    schema_and_iam.harvest_cors_preflight_capabilities,
    runtime_and_network.predict_and_verify_semantic_rest_endpoints,
    surface_prober.probe_api_versions_and_ghost_endpoints,
)

STAGE5_JS_AND_CLIENT_ENGINES = (
    active_web_auditor.unpack_js_sourcemaps,
    active_web_auditor.hunt_dependency_confusion_risks,
    active_web_auditor.harvest_and_audit_jwt_tokens,
    active_web_auditor.hunt_broken_external_links_and_script_hijack,
    protocol_and_client.analyze_postmessage_handlers,
    protocol_and_client.parse_service_worker_manifests,
    protocol_and_client.extract_client_storage_keys_and_checks,
    schema_and_iam.predict_and_fetch_webpack_chunks,
    schema_and_iam.mine_i18n_translation_dictionaries,
    runtime_and_network.headless_chrome_dom_and_route_renderer,
    runtime_and_network.analyze_wasm_binaries_and_server_timing,
)

STAGE6_CLOUD_AND_CORRELATION_ENGINES = (
    origin_and_spa.run_adaptive_brain_strategy,
    origin_and_spa.deconstruct_spa_manifests_and_ssr_state,
    origin_and_spa.hunt_deep_secrets_and_uz_ecosystem,
    origin_and_spa.mine_well_known_and_mobile_links,
    origin_and_spa.trace_redirect_chains_and_oauth_flows,
    origin_and_spa.extract_document_metadata_osint,
    active_web_auditor.enumerate_multicloud_and_containers,
    protocol_and_client.correlate_analytics_and_tag_ids,
    runtime_and_network.build_corporate_org_and_backend_correlation_graph,
)

