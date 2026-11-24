# frozen_string_literal: true

module EE
  module Gitlab
    module ApplicationRateLimiter
      module LabkitAdapter
        # EE-only entries for the labkit rate-limit adapter, merged into
        # the CE registry via prepend.
        #
        # See lib/gitlab/application_rate_limiter/labkit_adapter/supported_rate_limits.rb
        # for the conventions (AR-typed characteristics, limit/period, the
        # exclusion categories).
        module SupportedRateLimits
          extend ActiveSupport::Concern

          class_methods do
            extend ::Gitlab::Utils::Override

            override :rule_definitions
            def rule_definitions # rubocop:disable Metrics/AbcSize, -- static registry of EE rate-limit definitions
              super.merge(
                ai_agent_audit_event_ingest: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_ai_agent_audit_event_ingest_by_user_and_project',
                  characteristics: %i[user project],
                  limit: 10,
                  period: 1.minute,
                  action: :limit
                ),
                ai_agent_identity_registration: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_ai_agent_identity_registration_by_user_and_project',
                  characteristics: %i[user project],
                  limit: 10,
                  period: 1.minute,
                  action: :limit
                ),
                ai_agent_session_creation: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_ai_agent_session_creation_by_user_and_project',
                  characteristics: %i[user project],
                  limit: 10,
                  period: 1.minute,
                  action: :limit
                ),
                ai_agent_session_token_creation: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_ai_agent_session_token_creation_by_user_and_project',
                  characteristics: %i[user project],
                  limit: 10,
                  period: 1.minute,
                  action: :limit
                ),
                ai_agent_session_token_creation_by_user: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_ai_agent_session_token_creation_by_user',
                  characteristics: %i[user],
                  limit: 20,
                  period: 1.minute,
                  action: :limit
                ),
                # Counts events, not requests, across the Duo Workflow and external agent ingest endpoints.
                ai_audit_event_ingest_by_top_level_namespace: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_ai_audit_event_ingest_by_top_level_namespace',
                  characteristics: %i[namespace],
                  limit: 20_000,
                  period: 1.minute,
                  action: :limit
                ),
                ai_catalog_config_validation: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_ai_catalog_config_validation_by_user',
                  characteristics: %i[user],
                  limit: 30,
                  period: 1.minute,
                  action: :limit
                ),
                ai_catalog_item_consumer_bulk_create: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_ai_catalog_item_consumer_bulk_create_by_user',
                  characteristics: %i[user],
                  limit: 10,
                  period: 1.minute,
                  action: :limit
                ),
                ai_catalog_item_consumer_create: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_ai_catalog_item_consumer_create_by_user',
                  characteristics: %i[user],
                  limit: 30,
                  period: 1.minute,
                  action: :limit
                ),
                ai_catalog_item_consumer_delete: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_ai_catalog_item_consumer_delete_by_user',
                  characteristics: %i[user],
                  limit: 30,
                  period: 1.minute,
                  action: :limit
                ),
                ai_catalog_item_report: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_ai_catalog_item_reports_by_user',
                  characteristics: %i[user],
                  limit: 10,
                  period: 1.minute,
                  action: :limit
                ),
                ai_duo_workflow_audit_event_ingest: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_ai_duo_workflow_audit_event_ingest_by_user',
                  characteristics: %i[user],
                  limit: 120,
                  period: 1.minute,
                  action: :limit
                ),
                ai_governance_sessions_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_ai_governance_sessions_api_by_user_and_namespace',
                  characteristics: %i[user namespace],
                  limit: 120,
                  period: 1.minute,
                  action: :limit
                ),
                ai_model_selection_namespace_update: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_ai_model_selection_namespace_updates_by_user',
                  characteristics: %i[user],
                  limit: 30,
                  period: 1.minute,
                  action: :limit
                ),
                ai_session_artifact_download: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_ai_session_artifact_download_by_user',
                  characteristics: %i[user],
                  limit: 10,
                  period: 1.minute,
                  action: :limit
                ),
                ai_tool_rules_bulk_update: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_ai_tool_rules_bulk_updates_by_user',
                  characteristics: %i[user],
                  limit: 10,
                  period: 1.minute,
                  action: :limit
                ),
                # Counts distinct users per IP; see Ai::UsersPerIpLimit for who is counted.
                ai_users_per_ip: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_ai_distinct_users_by_ip',
                  characteristics: %i[ip],
                  limit: 5,
                  period: 1.day,
                  action: :limit,
                  count_distinct: :user_id
                ),
                anthropic_compliance_key_verification_by_group: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_anthropic_compliance_key_verifications_by_group',
                  characteristics: %i[group],
                  limit: 10,
                  period: 1.hour,
                  action: :limit
                ),
                anthropic_compliance_key_verification_by_user: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_anthropic_compliance_key_verifications_by_user',
                  characteristics: %i[user],
                  limit: 10,
                  period: 1.hour,
                  action: :limit
                ),
                artifact_registry_namespace_provisioning: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_artifact_registry_namespace_provisioning_by_organization',
                  characteristics: %i[organization],
                  limit: 10,
                  period: 1.hour,
                  action: :limit
                ),
                audit_event_streaming_destination_mutation: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_audit_event_streaming_destination_mutations_by_user',
                  characteristics: %i[user],
                  limit: 10,
                  period: 1.minute,
                  action: :limit
                ),
                audit_events_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_audit_events_api_by_user',
                  characteristics: %i[user],
                  limit: -> { ::Gitlab::CurrentSettings.current_application_settings.audit_events_api_limit },
                  period: 1.minute,
                  action: :limit
                ),
                ai_suggested_reviewers_create: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_ai_suggested_reviewers_creation_by_user_and_project',
                  characteristics: %i[user project],
                  limit: 60,
                  period: 1.minute,
                  action: :limit
                ),
                project_audit_events_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_project_audit_events_api_by_user_and_project',
                  characteristics: %i[user project],
                  limit: -> { ::Gitlab::CurrentSettings.current_application_settings.project_audit_events_api_limit },
                  period: 1.minute,
                  action: :limit
                ),
                group_audit_events_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_group_audit_events_api_by_user_and_group',
                  characteristics: %i[user group],
                  limit: -> { ::Gitlab::CurrentSettings.current_application_settings.group_audit_events_api_limit },
                  period: 1.minute,
                  action: :limit
                ),
                group_cascading_settings_update: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_cascading_settings_updates_by_group',
                  characteristics: %i[group],
                  limit: 10,
                  period: 10.minutes,
                  action: :limit
                ),
                user_cascading_settings_update: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_cascading_settings_updates_by_user',
                  characteristics: %i[user],
                  limit: 30,
                  period: 10.minutes,
                  action: :limit
                ),
                billed_users_scan_per_day: staged_rule(
                  enforce: ->(scope) { ::Feature.enabled?(:enforce_billed_users_scan_rate_limits, scope[:namespace]) },
                  name: 'limit_billed_users_scans_per_day_by_user_namespace',
                  characteristics: %i[user namespace],
                  limit: 10_000,
                  period: 1.day
                ),
                billed_users_scan_per_hour: staged_rule(
                  enforce: ->(scope) { ::Feature.enabled?(:enforce_billed_users_scan_rate_limits, scope[:namespace]) },
                  name: 'limit_billed_users_scans_per_hour_by_user_namespace',
                  characteristics: %i[user namespace],
                  limit: 1_000,
                  period: 1.hour
                ),
                billed_users_scan_per_minute: staged_rule(
                  enforce: ->(scope) { ::Feature.enabled?(:enforce_billed_users_scan_rate_limits, scope[:namespace]) },
                  name: 'limit_billed_users_scans_per_minute_by_user_namespace',
                  characteristics: %i[user namespace],
                  limit: 60,
                  period: 1.minute
                ),
                code_suggestions_connection_details: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_code_suggestions_connection_details_by_user',
                  characteristics: %i[user],
                  limit: 10,
                  period: 1.minute,
                  action: :limit
                ),
                code_suggestions_direct_access: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_code_suggestions_direct_access_by_user',
                  characteristics: %i[user],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                container_scanning_for_registry_scans: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_container_scanning_for_registry_scans_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.day,
                  action: :limit
                ),
                create_duo_otel_workflow: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_duo_otel_workflow_creates_by_user',
                  characteristics: %i[user],
                  limit: 5,
                  period: 1.minute,
                  action: :limit
                ),
                credit_card_verification_check_for_reuse: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_credit_card_verification_reuse_checks_by_ip',
                  characteristics: %i[ip],
                  limit: 10,
                  period: 1.hour,
                  action: :limit
                ),
                # Every dashboard create or config update writes a row of up to 64 KB.
                custom_dashboard_write: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_custom_dashboard_writes_by_user',
                  characteristics: %i[user],
                  limit: 30,
                  period: 1.minute,
                  action: :limit
                ),
                # Every view expands the project's CI config, including remote includes, in the web request.
                dast_configuration_show: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_dast_configuration_views_by_user',
                  characteristics: %i[user],
                  limit: 10,
                  period: 1.minute,
                  action: :limit
                ),
                dependency_firewall_enablement: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_dependency_firewall_enablement_by_user_or_ip',
                  characteristics: %i[user ip],
                  # Own bucket, but tracks project_api_limit rather than a fixed number, so an
                  # administrator who tunes project reads down does not leave this endpoint wide open.
                  limit: -> { ::Gitlab::CurrentSettings.current_application_settings.project_api_limit },
                  period: 1.minute,
                  action: :limit
                ),
                dependency_firewall_evaluation: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_dependency_firewall_evaluation_by_project',
                  characteristics: %i[project],
                  limit: 3000,
                  period: 1.minute,
                  action: :limit
                ),
                dependency_management_scheduler_run: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_dependency_management_scheduler_runs_by_project',
                  characteristics: %i[project],
                  limit: 1,
                  period: 5.minutes,
                  action: :limit
                ),
                # Separate from runs, because a reschedule is queued from inside an admitted run's window.
                dependency_management_scheduler_reschedule: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_dependency_management_scheduler_reschedules_by_project',
                  characteristics: %i[project],
                  limit: 1,
                  period: 5.minutes,
                  action: :limit
                ),
                dependency_scanning_sbom_scan_api_download: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_dependency_scanning_sbom_scan_api_downloads_by_project',
                  characteristics: %i[project],
                  limit: -> {
                    ::Gitlab::CurrentSettings.current_application_settings.dependency_scanning_sbom_scan_api_download_limit
                  },
                  period: 1.hour,
                  action: :limit
                ),
                dependency_scanning_sbom_scan_api_reuse: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_dependency_scanning_sbom_scan_api_reuses_by_project',
                  characteristics: %i[project],
                  # About 1.4x the highest per-project hourly peak in request logs from 2026-10-20
                  # to 2026-11-12 (gitlab-org/gitlab, 8,391 calls, 404 and 410 included), so no
                  # current project is throttled. Throttled requests are logged by the rate limiter.
                  limit: 12000,
                  period: 1.hour,
                  action: :limit
                ),
                dependency_scanning_sbom_scan_api_throttling: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_sbom_scan_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.hour,
                  action: :limit
                ),
                dependency_scanning_sbom_scan_api_upload: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_dependency_scanning_sbom_scan_api_uploads_by_project',
                  characteristics: %i[project],
                  limit: -> {
                    ::Gitlab::CurrentSettings.current_application_settings.dependency_scanning_sbom_scan_api_upload_limit
                  },
                  period: 1.hour,
                  action: :limit
                ),
                dial_code_phone_verification_transactions_limit: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_phone_verification_transactions_by_dial_code',
                  characteristics: %i[international_dial_code],
                  limit: ->(ctx) {
                    ctx&.dig(:threshold) ||
                      ::Gitlab::CurrentSettings.current_application_settings
                        .dial_code_phone_verification_transactions_daily_limit
                  },
                  period: 1.day,
                  action: :limit
                ),
                card_fingerprint_phone_verification_transactions_limit: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_phone_verification_transactions_by_card_fingerprint',
                  characteristics: %i[stripe_card_fingerprint],
                  limit: 5,
                  period: 1.day,
                  action: :limit
                ),
                duo_code_review_mention: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_duo_code_review_mentions_by_user',
                  characteristics: %i[user],
                  limit: 500,
                  period: 1.hour,
                  action: :limit
                ),
                duo_code_review_mention_limit_notice: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_duo_code_review_mention_limit_notices_by_user',
                  characteristics: %i[user],
                  limit: 1,
                  period: 1.hour,
                  action: :limit
                ),
                duo_workflow_direct_access: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_duo_workflow_direct_access_by_user',
                  characteristics: %i[user],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                github_oauth_webhook_delivery: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_github_oauth_webhook_deliveries_by_project',
                  characteristics: %i[project],
                  limit: 300,
                  period: 1.minute,
                  action: :limit
                ),
                hand_raise_lead_create: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_hand_raise_lead_create_by_user',
                  characteristics: %i[user],
                  limit: 10,
                  period: 1.hour,
                  action: :limit
                ),
                hard_phone_verification_transactions_limit: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_hard_phone_verification_transactions_by_scope',
                  characteristics: %i[scope],
                  limit: -> {
                    ::Gitlab::CurrentSettings.current_application_settings.hard_phone_verification_transactions_daily_limit
                  },
                  period: 1.day,
                  action: :limit
                ),
                merge_request_resync_security_policies: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_merge_request_resync_security_policies_by_merge_request',
                  characteristics: %i[merge_request],
                  limit: 1,
                  period: 1.minute,
                  action: :limit
                ),
                security_policies_resync: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_security_policies_resyncs_by_project_group',
                  characteristics: %i[project group],
                  limit: 1,
                  period: 1.hour,
                  action: :limit
                ),
                duo_workflow_project_search: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_duo_workflow_project_searches_by_user_project',
                  characteristics: %i[user project],
                  limit: 30,
                  period: 1.minute,
                  action: :limit
                ),
                duo_workflow_unauthorized_access: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_duo_workflow_unauthorized_access_by_user_workflow',
                  characteristics: %i[user duo_workflow],
                  limit: 1,
                  period: 5.minutes,
                  action: :limit
                ),
                epic_move_list: staged_rule(
                  enforce: ->(scope) { ::Feature.enabled?(:epic_move_list_rate_limit, scope[:user]) },
                  name: 'limit_epic_board_moves_by_user',
                  characteristics: %i[user],
                  limit: -> { ::Gitlab::CurrentSettings.current_application_settings.epic_move_list_limit },
                  period: 1.minute
                ),
                # Callers pass { user:, namespace: }, or { ip:, namespace: } when anonymous.
                insights_query: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_insights_queries_by_user_or_ip_and_namespace',
                  characteristics: %i[user ip namespace],
                  limit: -> { ::Gitlab::CurrentSettings.current_application_settings.insights_query_limit },
                  period: 1.minute,
                  action: :limit
                ),
                merge_train_removal: staged_rule(
                  enforce: ->(scope) { ::Feature.enabled?(:rate_limit_merge_train_removal, scope[:user]) },
                  name: 'limit_merge_train_removals_by_user',
                  characteristics: %i[user],
                  limit: -> {
                    ::Gitlab::CurrentSettings.current_application_settings.merge_train_removal_limit_per_user
                  },
                  period: 1.minute
                ),
                orbit_indexing_status: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_orbit_indexing_status_by_user',
                  characteristics: %i[user],
                  limit: -> { ::Gitlab::CurrentSettings.current_application_settings.orbit_indexing_status_limit },
                  period: 1.minute,
                  action: :limit
                ),
                orbit_item_counts: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_orbit_item_counts_by_user',
                  characteristics: %i[user],
                  limit: -> { ::Gitlab::CurrentSettings.current_application_settings.orbit_item_counts_limit },
                  period: 1.minute,
                  action: :limit
                ),
                orbit_query: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_orbit_queries_by_user',
                  characteristics: %i[user],
                  limit: -> { ::Gitlab::CurrentSettings.current_application_settings.orbit_query_limit },
                  period: 1.minute,
                  action: :limit
                ),
                package_metadata: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_package_metadata_queries_by_user',
                  characteristics: %i[user],
                  limit: 1000,
                  period: 1.hour,
                  action: :limit
                ),
                partner_aws_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_aws_api_by_project',
                  characteristics: %i[project],
                  limit: 400,
                  period: 1.second,
                  action: :limit
                ),
                partner_gcp_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_gcp_api_by_project',
                  characteristics: %i[project],
                  limit: 500,
                  period: 1.second,
                  action: :limit
                ),
                partner_postman_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_postman_api_by_project',
                  characteristics: %i[project],
                  limit: 4,
                  period: 1.second,
                  action: :limit
                ),
                partner_github_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_github_api_by_project',
                  characteristics: %i[project],
                  limit: 60,
                  period: 1.hour,
                  action: :limit
                ),
                partner_openai_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_openai_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_anthropic_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_anthropic_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_heroku_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_heroku_api_by_project',
                  characteristics: %i[project],
                  limit: 75,
                  period: 1.minute,
                  action: :limit
                ),
                partner_stripe_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_stripe_api_by_project',
                  characteristics: %i[project],
                  limit: 100,
                  period: 1.minute,
                  action: :limit
                ),
                partner_datadog_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_datadog_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_sendgrid_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_sendgrid_api_by_project',
                  characteristics: %i[project],
                  limit: 60,
                  period: 1.minute,
                  action: :limit
                ),
                partner_npm_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_npm_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_hashicorp_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_hashicorp_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_easypost_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_easypost_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_gocardless_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_gocardless_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_pulumi_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_pulumi_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_adafruit_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_adafruit_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_asana_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_asana_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_fastly_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_fastly_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_huggingface_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_huggingface_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_gcnotify_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_gcnotify_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_tailscale_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_tailscale_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_hubspot_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_hubspot_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_digitalocean_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_digitalocean_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_doppler_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_doppler_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_flutterwave_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_flutterwave_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_beamer_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_beamer_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_shippo_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_shippo_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_messagebird_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_messagebird_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_highnote_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_highnote_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_ionic_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_ionic_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_typeform_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_typeform_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_linear_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_linear_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_mailgun_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_mailgun_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_intercom_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_intercom_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_grafana_cloud_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_grafana_cloud_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_rubygems_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_rubygems_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_dropbox_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_dropbox_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                # Brevo allows 100 requests per hour on the account endpoint.
                partner_brevo_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_brevo_api_by_project',
                  characteristics: %i[project],
                  limit: 100,
                  period: 1.hour,
                  action: :limit
                ),
                partner_contentful_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_contentful_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_posthog_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_posthog_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_langchain_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_langchain_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_segment_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_segment_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_new_relic_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_new_relic_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_lob_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_lob_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                partner_onfido_api: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_partner_onfido_api_by_project',
                  characteristics: %i[project],
                  limit: 50,
                  period: 1.minute,
                  action: :limit
                ),
                # Each refresh queues a full billable users count over the users table.
                refresh_billable_users: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_billable_users_refreshes_by_user',
                  characteristics: %i[user],
                  limit: 1,
                  period: 10.minutes,
                  action: :limit
                ),
                scanned_resources_csv_download: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_scanned_resources_csv_downloads_by_user',
                  characteristics: %i[user],
                  limit: 5,
                  period: 1.minute,
                  action: :limit
                ),
                scanned_resources_graphql: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_scanned_resources_graphql_by_user',
                  characteristics: %i[user],
                  limit: 60,
                  period: 1.minute,
                  action: :limit
                ),
                seat_usage_export: staged_rule(
                  enforce: ->(scope) { ::Feature.enabled?(:enforce_billed_users_scan_rate_limits, scope[:namespace]) },
                  name: 'limit_seat_usage_exports_by_user_namespace',
                  characteristics: %i[user namespace],
                  limit: 10,
                  period: 1.hour
                ),
                # Each refresh bypasses the cached subscription service answers.
                secrets_manager_entitlement_refresh: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_secrets_manager_entitlement_refreshes_by_user',
                  characteristics: %i[user],
                  limit: 10,
                  period: 1.minute,
                  action: :limit
                ),
                # Each secrets manager adds an OpenBao namespace, and OpenBao loads
                # every namespace on startup and failover.
                secrets_manager_initialize: staged_rule(
                  enforce: ->(scope) {
                    ::Feature.enabled?(:secrets_manager_initialize_rate_limit, scope[:namespace])
                  },
                  name: 'limit_secrets_manager_initializations_by_root_namespace',
                  characteristics: %i[namespace],
                  limit: 30,
                  period: 1.minute
                ),
                security_ai_flow_feedback_create: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_security_ai_flow_feedback_creation_by_user',
                  characteristics: %i[user],
                  limit: 60,
                  period: 1.minute,
                  action: :limit
                ),
                semantic_code_search_ad_hoc_indexing: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_semantic_code_search_ad_hoc_indexing_by_namespace',
                  characteristics: %i[namespace],
                  limit: 10,
                  period: 1.hour,
                  action: :limit
                ),
                semantic_search_rate_limit: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_semantic_searches_by_user',
                  characteristics: %i[user],
                  limit: 10,
                  period: 1.minute,
                  action: :limit
                ),
                soft_phone_verification_transactions_limit: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_soft_phone_verification_transactions_by_scope',
                  characteristics: %i[scope],
                  limit: -> {
                    ::Gitlab::CurrentSettings.current_application_settings.soft_phone_verification_transactions_daily_limit
                  },
                  period: 1.day,
                  action: :limit
                ),
                credits_usage_per_day: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_credits_usage_per_day_by_user',
                  characteristics: %i[user],
                  limit: -> {
                    ::Gitlab::CurrentSettings.current_application_settings.credits_usage_per_day_limit
                  },
                  period: 1.day,
                  action: :limit
                ),
                credits_usage_per_hour: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_credits_usage_per_hour_by_user',
                  characteristics: %i[user],
                  limit: -> {
                    ::Gitlab::CurrentSettings.current_application_settings.credits_usage_per_hour_limit
                  },
                  period: 1.hour,
                  action: :limit
                ),
                credits_usage_per_minute: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_credits_usage_per_minute_by_user',
                  characteristics: %i[user],
                  limit: -> {
                    ::Gitlab::CurrentSettings.current_application_settings.credits_usage_per_minute_limit
                  },
                  period: 1.minute,
                  action: :limit
                ),
                budget_cap_update_per_day: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_budget_cap_updates_per_day_by_user',
                  characteristics: %i[user],
                  limit: -> {
                    ::Gitlab::CurrentSettings.current_application_settings.budget_cap_update_per_day_limit
                  },
                  period: 1.day,
                  action: :limit
                ),
                budget_cap_update_per_hour: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_budget_cap_updates_per_hour_by_user',
                  characteristics: %i[user],
                  limit: -> {
                    ::Gitlab::CurrentSettings.current_application_settings.budget_cap_update_per_hour_limit
                  },
                  period: 1.hour,
                  action: :limit
                ),
                budget_cap_update_per_minute: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_budget_cap_updates_per_minute_by_user',
                  characteristics: %i[user],
                  limit: -> {
                    ::Gitlab::CurrentSettings.current_application_settings.budget_cap_update_per_minute_limit
                  },
                  period: 1.minute,
                  action: :limit
                ),
                subscription_usage_per_day: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_subscription_usage_per_day_by_user',
                  characteristics: %i[user],
                  limit: -> {
                    ::Gitlab::CurrentSettings.current_application_settings.subscription_usage_per_day_limit
                  },
                  period: 1.day,
                  action: :limit
                ),
                subscription_usage_per_hour: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_subscription_usage_per_hour_by_user',
                  characteristics: %i[user],
                  limit: -> {
                    ::Gitlab::CurrentSettings.current_application_settings.subscription_usage_per_hour_limit
                  },
                  period: 1.hour,
                  action: :limit
                ),
                subscription_usage_per_minute: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_subscription_usage_per_minute_by_user',
                  characteristics: %i[user],
                  limit: -> {
                    ::Gitlab::CurrentSettings.current_application_settings.subscription_usage_per_minute_limit
                  },
                  period: 1.minute,
                  action: :limit
                ),
                tasks_by_type: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_tasks_by_type_by_user_and_group',
                  characteristics: %i[user group],
                  limit: 20,
                  period: 1.minute,
                  action: :limit
                ),
                trial_create: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_trial_create_by_user',
                  characteristics: %i[user],
                  limit: 10,
                  period: 1.hour,
                  action: :limit
                ),
                # Set-based unique-cardinality rate limits.
                # `count_distinct: :project_id` flips the rule from INCR to
                # SADD/SCARD on labkit; the SET member is the downloaded
                # project's id, set explicitly by the adapter (not class-routed
                # through characteristics, hence the `_id` suffix to make the
                # bare assignment unambiguous).
                #
                # Per-call `threshold:`/`interval:` overrides route through
                # labkit's `rule_context:` keyword for every key. The namespace
                # key carries placeholder limit/period (0/0, matching the legacy
                # registry); real values live on namespace_settings and arrive
                # per-call, so this plumbing is load-bearing for it.
                unique_project_downloads_for_application: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_unique_project_downloads_by_user',
                  characteristics: %i[user],
                  limit: ->(ctx) {
                    ctx&.dig(:threshold) || ::Gitlab::CurrentSettings.current_application_settings.max_number_of_repository_downloads
                  },
                  period: ->(ctx) {
                    ctx&.dig(:interval) || ::Gitlab::CurrentSettings.current_application_settings.max_number_of_repository_downloads_within_time_period
                  },
                  action: :limit,
                  count_distinct: :project_id
                ),
                unique_project_downloads_for_namespace: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_unique_project_downloads_by_user_namespace',
                  characteristics: %i[user namespace],
                  limit: ->(ctx) { ctx&.dig(:threshold) || 0 },
                  period: ->(ctx) { ctx&.dig(:interval) || 0 },
                  action: :limit,
                  count_distinct: :project_id
                ),
                virtual_registries_endpoints_api_limit: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_virtual_registries_endpoints_api_by_ip_group',
                  characteristics: %i[ip group],
                  limit: -> {
                    ::Gitlab::CurrentSettings.current_application_settings.virtual_registries_endpoints_api_limit
                  },
                  period: 15.seconds,
                  action: :limit
                ),
                vulnerability_bulk_dismiss: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_vulnerability_bulk_dismissals_by_user',
                  characteristics: %i[user],
                  limit: 520,
                  period: 1.minute,
                  action: :limit
                ),
                vulnerability_bulk_dismiss_hourly: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_vulnerability_bulk_dismissals_hourly_by_user',
                  characteristics: %i[user],
                  limit: 11_200,
                  period: 1.hour,
                  action: :limit
                ),
                vulnerability_severity_override: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_vulnerability_severity_overrides_by_user',
                  characteristics: %i[user],
                  limit: 160,
                  period: 1.minute,
                  action: :limit
                ),
                vulnerability_severity_override_hourly: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_vulnerability_severity_overrides_hourly_by_user',
                  characteristics: %i[user],
                  limit: 4_000,
                  period: 1.hour,
                  action: :limit
                ),
                # EE overrides the CE code suggestions API endpoint threshold/interval.
                code_suggestions_api_endpoint: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_code_suggestions_by_user',
                  characteristics: %i[user],
                  limit: 60,
                  period: 1.minute,
                  action: :limit
                ),
                # EE overrides the CE Geo proxy threshold/interval.
                geo_proxy: ::Labkit::RateLimit::Rule.new(
                  name: 'limit_geo_proxy_requests_by_ip',
                  characteristics: %i[ip],
                  limit: 3600,
                  period: 1.minute,
                  action: :limit
                )
              )
            end
          end
        end
      end
    end
  end
end
