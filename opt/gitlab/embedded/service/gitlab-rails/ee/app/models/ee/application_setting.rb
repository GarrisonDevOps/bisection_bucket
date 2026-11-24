# frozen_string_literal: true

module EE
  # ApplicationSetting EE mixin
  #
  # This module is intended to encapsulate EE-specific model logic
  # and be prepended in the `ApplicationSetting` model
  module ApplicationSetting
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    prepended do
      include ::Ai::CodeReview::DepthSettings

      EMAIL_ADDITIONAL_TEXT_CHARACTER_LIMIT = 10_000
      MASK_PASSWORD = '*****'
      ELASTIC_REQUEST_TIMEOUT = 30
      SEAT_CONTROL_OFF = 0
      SEAT_CONTROL_USER_CAP = 1
      SEAT_CONTROL_BLOCK_OVERAGES = 2

      ERROR_NO_SEATS_AVAILABLE = 'NO_SEATS_AVAILABLE'

      belongs_to :file_template_project, class_name: "Project"
      belongs_to :duo_template_project, class_name: 'Project', optional: true
      belongs_to :workspaces_oauth_application, class_name: 'Doorkeeper::Application', optional: true

      # Per-cell AI infrastructure configuration, moved here from the
      # (organization-scoped) ai_settings table.
      validates :ai_gateway_url, :duo_agent_platform_service_url, length: { maximum: 2048 }, allow_nil: true

      validate :validate_ai_gateway_url

      validates :ai_gateway_timeout_seconds,
        numericality: {
          greater_than_or_equal_to: 60,
          less_than_or_equal_to: 600
        },
        allow_nil: true

      jsonb_accessor :search,
        global_search_code_enabled: [:boolean, { default: true }],
        global_search_commits_enabled: [:boolean, { default: true }],
        global_search_notes_enabled: [:boolean, { default: true }],
        global_search_wiki_enabled: [:boolean, { default: true }],
        global_search_limited_indexing_enabled: [:boolean, { default: false }],
        elastic_migration_worker_enabled: [:boolean, { default: true }]

      jsonb_accessor :active_context_settings,
        active_context_pause_indexing: [:boolean, { default: false }]

      jsonb_accessor :zoekt_settings,
        zoekt_cache_response: [:boolean, { default: true }],
        zoekt_indexing_enabled: [:boolean, { default: false }],
        zoekt_indexing_paused: [:boolean, { default: false }],
        zoekt_search_enabled: [:boolean, { default: false }],
        zoekt_auto_index_root_namespace: [:boolean, { default: false }],
        zoekt_cpu_to_tasks_ratio: [:float, { default: 1.0 }],
        zoekt_trigram_max: [:integer, { default: ::Search::Zoekt::Settings::DEFAULT_TRIGRAM_MAX }],
        zoekt_indexed_file_size_limit: [:text, { default: ::Search::Zoekt::Settings::DEFAULT_FILE_SIZE_LIMIT }],
        zoekt_indexing_parallelism: [:integer, { default: 1 }],
        zoekt_rollout_batch_size: [:integer, { default: 32 }],
        zoekt_indexing_timeout: [:text, { default: ::Search::Zoekt::Settings::DEFAULT_INDEXING_TIMEOUT }],
        zoekt_maximum_files: [:integer, { default: ::Search::Zoekt::Settings::DEFAULT_MAXIMUM_FILES }],
        zoekt_rollout_retry_interval: [:text, { default: ::Search::Zoekt::Settings::DEFAULT_ROLLOUT_RETRY_INTERVAL }],
        zoekt_lost_node_threshold: [:text, { default: ::Search::Zoekt::Settings::DEFAULT_LOST_NODE_THRESHOLD }],
        zoekt_default_number_of_replicas: [:integer, { default: ::Search::Zoekt::Settings::DEFAULT_NUM_REPLICAS }],
        zoekt_force_reindexing_percentage: [:float,
          { default: ::Search::Zoekt::Settings::DEFAULT_FORCE_REINDEXING_PERCENTAGE }],
        zoekt_max_projects_for_legacy_search: [:integer,
          { default: ::Search::Zoekt::Settings::DEFAULT_MAX_PROJECTS_LEGACY_SEARCH }],
        zoekt_max_restarts_15m: [:integer, { default: ::Search::Zoekt::Settings::DEFAULT_MAX_RESTARTS_15M }],
        zoekt_initial_indexing_limit: [:integer,
          { default: ::Search::Zoekt::Settings::DEFAULT_INITIAL_INDEXING_LIMIT }]

      jsonb_accessor :orbit_settings,
        orbit_auto_index_root_namespace: [:boolean, { default: false }],
        orbit_dap_enabled_by_default: [:boolean, { default: true }]

      jsonb_accessor :code_creation,
        disabled_direct_code_suggestions: [:boolean, { default: false }],
        model_prompt_cache_enabled: [:boolean, { default: true }],
        lock_model_prompt_cache_enabled: [:boolean, { default: false }]

      validates :code_creation, json_schema: { filename: "application_setting_code_creation" }

      jsonb_accessor :duo_workflow,
        duo_workflow_oauth_application_id: [:integer]

      jsonb_accessor :duo_settings,
        duo_custom_agents_enabled: [:boolean, { default: true }],
        lock_duo_custom_agents_enabled: [:boolean, { default: false }],
        duo_custom_flows_enabled: [:boolean, { default: true }],
        lock_duo_custom_flows_enabled: [:boolean, { default: false }],
        duo_external_agents_enabled: [:boolean, { default: true }],
        lock_duo_external_agents_enabled: [:boolean, { default: false }],
        ai_agent_governance_enforcement: [:integer, { default: 0 }],
        lock_ai_agent_governance_enforcement: [:boolean, { default: false }],
        duo_token_usage_retention_days: [:integer, { default: 1095 }]

      jsonb_accessor :duo_chat,
        duo_chat_expiration_days: [:integer, { default: 30 }],
        duo_chat_expiration_column: [:string, { default: 'last_updated_at' }]

      validates :duo_chat, json_schema: { filename: "application_setting_duo_chat" }
      validates :duo_chat_expiration_column, inclusion: {
        in: Ai::Conversation::Thread::EXPIRATION_COLUMNS,
        message: "must be one of: #{Ai::Conversation::Thread::EXPIRATION_COLUMNS.join(', ')}"
      }

      # Accepts a registry host, a registry path prefix ending in `/`, or a full image reference
      validates :duo_workflows_default_image_registry,
        allow_blank: true,
        length: { maximum: 512 },
        format: {
          with: %r{\A[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?
            (/[a-z0-9._-]+)*(:[a-z0-9._-]+|@sha256:[a-f0-9]{64}|/)?\z}ix,
          message: 'must be a valid hostname with optional port (e.g., registry.example.com:5000), ' \
            'a registry path prefix ending in / (e.g., harbor.example.com/proxy/), ' \
            'or full path to docker image (supports :tag and @sha256: digest pinning)'
        }
      before_validation :normalize_duo_workflows_default_image_registry
      before_validation :normalize_ci_telemetry_otel_endpoint

      validates :ci_telemetry_otel_endpoint,
        allow_blank: true,
        length: { maximum: 1024 },
        addressable_url: ::ApplicationSetting::ADDRESSABLE_URL_VALIDATION_OPTIONS.merge({ schemes: %w[http https] })

      validates :ci_job_telemetry_sampling_rate,
        numericality: { greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0 },
        allow_nil: true

      jsonb_accessor :usage_billing,
        display_gitlab_credits_user_data: [:boolean, { default: true }]

      validates :usage_billing, json_schema: { filename: "usage_billing_settings" }

      jsonb_accessor :nats_settings,
        use_nats_for_audit_streaming: [:boolean, { default: false }]

      validates :nats_settings, json_schema: { filename: "application_setting_nats_settings" }

      jsonb_accessor :integrations,
        allow_all_integrations: [:boolean, { default: true }],
        allowed_integrations: [:string, { array: true, default: [] }]

      jsonb_accessor :elasticsearch,
        elasticsearch_aws: [:boolean, { default: false }],
        elasticsearch_search: [:boolean, { default: false }],
        elasticsearch_indexing: [:boolean, { default: false }],
        elasticsearch_username: [:string],
        elasticsearch_aws_region: [:string, { default: 'us-east-1' }],
        elasticsearch_aws_role_arn: [:string],
        elasticsearch_aws_access_key: [:string],
        elasticsearch_client_adapter: [:text, { default: 'typhoeus' }],
        elasticsearch_limit_indexing: [:boolean, { default: false }],
        elasticsearch_pause_indexing: [:boolean, { default: false }],
        elasticsearch_advanced_search_pause_indexing: [:boolean, { default: false }],
        elasticsearch_requeue_workers: [:boolean, { default: false }],
        elasticsearch_max_bulk_size_mb: [:integer, { default: 10 }],
        elasticsearch_retry_on_failure: [:integer, { default: 0 }],
        elasticsearch_max_bulk_concurrency: [:integer, { default: 10 }],
        elasticsearch_client_request_timeout: [:integer, { default: 0 }],
        elasticsearch_worker_number_of_shards: [:integer, { default: 2 }],
        elasticsearch_analyzers_smartcn_search: [:boolean, { default: false }],
        elasticsearch_analyzers_kuromoji_search: [:boolean, { default: false }],
        elasticsearch_analyzers_smartcn_enabled: [:boolean, { default: false }],
        elasticsearch_analyzers_kuromoji_enabled: [:boolean, { default: false }],
        elasticsearch_indexed_field_length_limit: [:integer, { default: 0 }],
        elasticsearch_indexed_file_size_limit_kb: [:integer, { default: 1024 }],
        elasticsearch_indexing_timeout_minutes: [:integer, { default: ::Search::Elastic::Indexer::TIMEOUT_MINUTES }],
        elasticsearch_max_code_indexing_concurrency: [:integer, { default: 30 }],
        elasticsearch_prefix: [:string, { default: 'gitlab' }],
        elasticsearch_code_scope: [:boolean, { default: true }]

      validates :search, json_schema: { filename: 'application_setting_ee_search' }
      validates :duo_workflow, json_schema: { filename: "application_setting_duo_workflow" }
      validates :duo_settings, json_schema: { filename: "application_setting_duo_settings" }
      validates :ai_agent_governance_enforcement,
        numericality: { only_integer: true },
        inclusion: { in: ::Ai::Governance::AgentCredentialEnforcement::MODES.values },
        'ai/governance/enforcement_mode_input': true,
        if: :will_save_change_to_ai_agent_governance_enforcement?
      validates :elasticsearch, json_schema: { filename: "application_setting_elasticsearch" }
      validates :active_context_settings, json_schema: { filename: 'application_setting_active_context_settings' }

      jsonb_accessor :rate_limits, rate_limits_definition
      jsonb_accessor :ci_cd_settings, ci_cd_settings_definition

      jsonb_accessor :identity_verification_settings,
        soft_phone_verification_transactions_daily_limit: [::Gitlab::Database::Type::JsonbInteger.new,
          { default: 16_000 }],
        hard_phone_verification_transactions_daily_limit: [::Gitlab::Database::Type::JsonbInteger.new,
          { default: 20_000 }],
        unverified_account_group_creation_limit: [::Gitlab::Database::Type::JsonbInteger.new, { default: 2 }],
        phone_verification_enabled: [::Gitlab::Database::Type::JsonbBoolean.new, { default: true }],
        ci_requires_identity_verification_on_free_plan: [::Gitlab::Database::Type::JsonbBoolean.new, { default: true }],
        telesign_intelligence_enabled: [::Gitlab::Database::Type::JsonbBoolean.new, { default: true }],
        credit_card_verification_enabled: [::Gitlab::Database::Type::JsonbBoolean.new, { default: true }],
        arkose_labs_enabled: [::Gitlab::Database::Type::JsonbBoolean.new, { default: true }],
        arkose_labs_data_exchange_enabled: [::Gitlab::Database::Type::JsonbBoolean.new, { default: true }],
        sms_cost_restricted_dial_codes: [:integer, { array: true, default: [] }],
        dial_code_phone_verification_transactions_daily_limit: [::Gitlab::Database::Type::JsonbInteger.new,
          { default: 50 }],
        dial_code_phone_verification_transactions_daily_limit_overrides: [:jsonb,
          { default: {} }]

      validates :identity_verification_settings,
        json_schema: { filename: "identity_verification_settings", detail_errors: true }

      jsonb_accessor :cluster_agents,
        receptive_cluster_agents_enabled: [:boolean, { default: false }]

      jsonb_accessor :user_seat_management,
        seat_control: [:integer, { default: SEAT_CONTROL_OFF }]

      validates :user_seat_management, json_schema: { filename: "application_setting_user_seat_management" }

      validates :shared_runners_minutes,
        numericality: { greater_than_or_equal_to: 0 }

      validates :mirror_max_delay,
        numericality: { only_integer: true, greater_than: :mirror_max_delay_in_minutes }

      validate :mirror_capacity_threshold_less_than

      jsonb_accessor :observability_settings,
        fetch_observability_alerts_from_cloud: [:boolean, { default: true }]

      validates :observability_settings, json_schema: { filename: "application_setting_observability_settings" }

      SECURITY_MR_REPORT_CACHE_LIFETIME_MINUTES_DEFAULT = 10
      SECURITY_MR_REPORT_CACHE_LIFETIME_MINUTES_MIN = 10
      SECURITY_MR_REPORT_CACHE_LIFETIME_MINUTES_MAX = 60

      SECURITY_SCAN_STALE_AFTER_DAYS_DEFAULT_GITLAB_COM = 30
      SECURITY_SCAN_STALE_AFTER_DAYS_DEFAULT_SELF_MANAGED = 90
      SECURITY_SCAN_STALE_AFTER_DAYS_MIN = 7
      SECURITY_SCAN_STALE_AFTER_DAYS_MAX = 90

      jsonb_accessor :security_and_compliance_settings,
        enforce_pipl_compliance: [::Gitlab::Database::Type::JsonbBoolean.new, { default: false }],
        secret_push_protection_available: [::Gitlab::Database::Type::JsonbBoolean.new, { default: false }],
        secret_push_protection_enforced: [::Gitlab::Database::Type::JsonbBoolean.new, { default: false }],
        dependency_firewall_enabled: [::Gitlab::Database::Type::JsonbBoolean.new, { default: false }],
        security_mr_report_cache_lifetime_minutes: [:integer],
        security_scan_stale_after_days: [:integer],
        vac_project_ids: [:integer, { array: true, default: [] }]

      validates :security_and_compliance_settings,
        json_schema: { filename: "security_and_compliance_settings", detail_errors: true }

      validates :security_mr_report_cache_lifetime_minutes,
        allow_nil: true,
        numericality: {
          only_integer: true,
          greater_than_or_equal_to: SECURITY_MR_REPORT_CACHE_LIFETIME_MINUTES_MIN,
          less_than_or_equal_to: SECURITY_MR_REPORT_CACHE_LIFETIME_MINUTES_MAX,
          message: N_('must be between 10 and 60 minutes')
        }

      validates :security_scan_stale_after_days,
        allow_nil: true,
        numericality: {
          only_integer: true,
          greater_than_or_equal_to: SECURITY_SCAN_STALE_AFTER_DAYS_MIN,
          less_than_or_equal_to: SECURITY_SCAN_STALE_AFTER_DAYS_MAX,
          message: N_('must be between 7 and 90 days')
        }

      jsonb_accessor :secrets_manager_settings,
        project_secrets_limit: [:integer, { default: 100 }],
        group_secrets_limit: [:integer, { default: 500 }]

      validates :secrets_manager_settings,
        json_schema: { filename: "application_setting_secrets_manager_settings" }

      encrypts :sdrs_jwt_signing_key

      validates :sdrs_jwt_signing_key, json_schema: { filename: 'application_setting_sdrs_jwt_signing_key' },
        allow_nil: true
      validates :sdrs_jwt_signing_key, length: { maximum: 10_000 }

      validates :mirror_capacity_threshold,
        :mirror_max_capacity,
        :elasticsearch_indexed_file_size_limit_kb,
        :elasticsearch_indexing_timeout_minutes,
        :elasticsearch_max_bulk_concurrency,
        :elasticsearch_max_bulk_size_mb,
        numericality: { only_integer: true, greater_than: 0 }

      validates :elasticsearch_max_code_indexing_concurrency,
        :elasticsearch_retry_on_failure,
        presence: true,
        numericality: { only_integer: true, greater_than_or_equal_to: 0 }

      validates :namespace_storage_forks_cost_factor,
        presence: true,
        numericality: { greater_than_or_equal_to: 0, less_than_or_equal_to: 1 }

      validates :elasticsearch_url,
        presence: { message: "can't be blank when indexing is enabled" },
        if: ->(setting) { setting.elasticsearch_indexing? }

      validates :elasticsearch_username, length: { maximum: 255 }
      validates :elasticsearch_password, length: { maximum: 255 }

      validates :elasticsearch_prefix,
        presence: true,
        length: { minimum: 1, maximum: 100 },
        format: {
          with: /\A[a-z0-9]([a-z0-9_-]*[a-z0-9])?\z/,
          message: 'must contain only lowercase alphanumeric characters, hyphens, ' \
            'and underscores, and cannot start or end with a hyphen or underscore'
        }

      validates :elasticsearch_client_adapter, inclusion: { in: %w[typhoeus net_http] }

      validate :elasticsearch_prefix_no_whitespace

      validate :check_elasticsearch_url_scheme, if: :elasticsearch_url_changed?

      validate :check_allowed_integrations, if: :allowed_integrations_changed?

      validates :elasticsearch_aws_region,
        presence: { message: "can't be blank when using aws hosted elasticsearch" },
        if: ->(setting) { setting.elasticsearch_aws? && setting.elasticsearch_indexing? }

      validates :elasticsearch_worker_number_of_shards,
        presence: true,
        numericality: { only_integer: true, greater_than: 0,
                        less_than_or_equal_to: Elastic::ProcessBookkeepingService::SHARDS_MAX }

      validates :email_additional_text,
        allow_blank: true,
        length: { maximum: EMAIL_ADDITIONAL_TEXT_CHARACTER_LIMIT }

      attribute :future_subscriptions, ::Gitlab::Database::Type::IndifferentJsonb.new
      validates :future_subscriptions, json_schema: { filename: 'future_subscriptions' }

      validates :required_instance_ci_template, presence: true, allow_nil: true

      validates :geo_node_allowed_ips, length: { maximum: 255 }, presence: true
      validate :check_geo_node_allowed_ips

      validates :globally_allowed_ips, length: { maximum: 255 }, allow_blank: true
      validate :check_globally_allowed_ips

      validates :max_personal_access_token_lifetime,
        :max_ssh_key_lifetime,
        allow_blank: true,
        numericality: { only_integer: true, greater_than: 0, less_than_or_equal_to: :max_auth_lifetime }

      validates :new_user_signups_cap, absence: true, if: -> {
        [SEAT_CONTROL_OFF, SEAT_CONTROL_BLOCK_OVERAGES].include?(seat_control)
      }

      validates :new_user_signups_cap,
        numericality: { only_integer: true, greater_than: 0 }, if: -> { seat_control == SEAT_CONTROL_USER_CAP }

      validates :git_two_factor_session_expiry,
        presence: true,
        numericality: { only_integer: true, greater_than_or_equal_to: 1, less_than_or_equal_to: 10080 }

      validates :max_number_of_repository_downloads,
        numericality: { only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 10_000 }

      validates :max_number_of_repository_downloads_within_time_period,
        numericality: { only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 10.days.to_i }

      validates :git_rate_limit_users_allowlist,
        length: { maximum: 100, message: ->(_object, _data) { _("exceeds maximum length (100 usernames)") } },
        allow_nil: false,
        user_existence: true,
        if: :git_rate_limit_users_allowlist_changed?

      validates :git_rate_limit_users_alertlist,
        length: { maximum: 100, message: ->(_object, _data) { _("exceeds maximum length (100 user ids)") } },
        allow_nil: false,
        user_id_existence: true,
        if: :git_rate_limit_users_alertlist_changed?

      validates :dashboard_limit,
        :repository_size_limit,
        :audit_events_api_limit,
        :project_audit_events_api_limit,
        :group_audit_events_api_limit,
        :dependency_scanning_sbom_scan_api_upload_limit,
        :dependency_scanning_sbom_scan_api_download_limit,
        :elasticsearch_indexed_field_length_limit,
        :elasticsearch_client_request_timeout,
        :virtual_registries_endpoints_api_limit,
        :epic_move_list_limit,
        :insights_query_limit,
        :merge_train_removal_limit_per_user,
        :orbit_query_limit,
        :orbit_indexing_status_limit,
        :orbit_item_counts_limit,
        :subscription_usage_per_minute_limit,
        :subscription_usage_per_hour_limit,
        :subscription_usage_per_day_limit,
        :budget_cap_update_per_minute_limit,
        :budget_cap_update_per_hour_limit,
        :budget_cap_update_per_day_limit,
        :credits_usage_per_minute_limit,
        :credits_usage_per_hour_limit,
        :credits_usage_per_day_limit,
        numericality: { only_integer: true, greater_than_or_equal_to: 0 }

      validates :service_desk_paid_namespace_probation_days,
        numericality: { only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 365 }

      validates :orbit_rate_limit_allowlist,
        length: { maximum: 100, message: N_('is too long (maximum is 100 entries)') },
        allow_nil: false

      validates :cube_api_base_url,
        length: { maximum: 512 },
        addressable_url: ::ApplicationSetting::ADDRESSABLE_URL_VALIDATION_OPTIONS.merge({ allow_localhost: true }),
        presence: true,
        if: :product_analytics_enabled

      validates :product_analytics_enabled,
        presence: true,
        allow_blank: true

      validates :cube_api_key,
        length: { maximum: 255 },
        presence: true,
        if: :product_analytics_enabled

      validates :product_analytics_configurator_connection_string,
        length: { maximum: 512 },
        addressable_url: ::ApplicationSetting::ADDRESSABLE_URL_VALIDATION_OPTIONS.merge({ allow_localhost: true }),
        presence: true,
        if: ->(setting) { setting.product_analytics_enabled }

      validates :security_approval_policies_limit,
        numericality: {
          only_integer: true,
          greater_than_or_equal_to: 5,
          less_than_or_equal_to: ::Security::ScanResultPolicy::POLICIES_LIMIT
        }

      validates :security_policies, json_schema: { filename: "application_setting_security_policies" }

      jsonb_accessor :security_policies, scan_execution_policies_action_limit: [:integer, { default: 0 }]
      jsonb_accessor :security_policies, scan_execution_policies_schedule_limit: [:integer, { default: 0 }]
      jsonb_accessor :security_policies, pipeline_execution_policies_per_configuration_limit: [:integer, { default: 5 }]
      jsonb_accessor :security_policies, scan_execution_policies_per_configuration_limit: [:integer, { default: 5 }]
      jsonb_accessor :security_policies,
        vulnerability_management_policies_per_configuration_limit: [:integer, { default: 5 }]
      jsonb_accessor :security_policies,
        dependency_firewall_policies_per_configuration_limit: [:integer, { default: 5 }]
      jsonb_accessor :security_policies, policy_store_experiment_enabled: [:boolean, { default: false }]

      attr_accessor :secret_push_protection_mode

      before_validation :set_secret_push_protection_from_mode

      validates :scan_execution_policies_action_limit,
        numericality: { only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 20 }
      validates :scan_execution_policies_schedule_limit,
        numericality: { only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 20 }
      validates :pipeline_execution_policies_per_configuration_limit,
        numericality: { only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 20 }
      validates :scan_execution_policies_per_configuration_limit,
        numericality: { only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 20 }
      validates :vulnerability_management_policies_per_configuration_limit,
        numericality: { only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 20 }
      validates :dependency_firewall_policies_per_configuration_limit,
        numericality: { only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 20 }
      validates :default_security_tracked_context_quota,
        numericality: { only_integer: true, greater_than_or_equal_to: 1, allow_nil: true },
        if: -> { respond_to?(:default_security_tracked_context_quota) }

      validates :product_analytics_data_collector_host,
        length: { maximum: 255 },
        addressable_url: ::ApplicationSetting::ADDRESSABLE_URL_VALIDATION_OPTIONS.merge({ allow_localhost: true }),
        presence: true,
        if: :product_analytics_enabled

      validates :package_metadata_purl_types, inclusion: { in: ::Enums::Sbom.purl_types.values }

      validates :delete_unconfirmed_users,
        inclusion: { in: [true, false], message: N_('must be a boolean value') },
        unless: :email_confirmation_setting_off?

      validates :delete_unconfirmed_users,
        inclusion: { in: [false], message: N_('must be false when email confirmation setting is off') },
        if: :email_confirmation_setting_off?

      validates :unconfirmed_users_delete_after_days,
        numericality: { only_integer: true, greater_than: 0 },
        unless: :email_confirmation_setting_soft?

      validates :unconfirmed_users_delete_after_days,
        numericality: { only_integer: true, greater_than: proc { Devise.allow_unconfirmed_access_for.in_days.to_i } },
        if: :email_confirmation_setting_soft?

      validates :zoekt_settings, json_schema: { filename: 'application_setting_zoekt_settings' }
      validates :orbit_settings, json_schema: { filename: 'application_setting_orbit_settings' }
      validates :zoekt_cpu_to_tasks_ratio, numericality: { greater_than: 0.0 }
      validates :zoekt_indexing_parallelism, numericality: { greater_than: 0 }
      validates :zoekt_default_number_of_replicas, numericality: { greater_than: 0 }
      validates :zoekt_trigram_max, numericality: { only_integer: true, greater_than: 0 }
      validates :zoekt_force_reindexing_percentage,
        numericality: { greater_than_or_equal_to: 0, less_than_or_equal_to: 100 }
      validates :zoekt_indexed_file_size_limit, format: {
        with: ::Search::Zoekt::Settings::SIZE_REGEX,
        message: N_('Must be in the following format: `5B`, `5b`, `1KB`, `1kb`, `2MB`, `2mb`, `1GB`, or `1gb`')
      }
      validates :zoekt_rollout_batch_size, numericality: { greater_than: 0 }
      validates :zoekt_indexing_timeout, format: {
        with: ::Search::Zoekt::Settings::DURATION_INTERVAL_DISABLED_NOT_ALLOWED_REGEX,
        message: N_('Must be in the following format: `30m`, `2h`, or `1d`')
      }
      validates :zoekt_maximum_files, numericality: { greater_than: 0 }
      validates :zoekt_max_restarts_15m, numericality: { only_integer: true, greater_than_or_equal_to: 0 }
      validates :zoekt_initial_indexing_limit, numericality: {
        only_integer: true, greater_than: 0, less_than_or_equal_to: ::Search::Zoekt::Settings::MAX_INITIAL_INDEXING_LIMIT
      }
      validates :zoekt_rollout_retry_interval, format: {
        with: ::Search::Zoekt::Settings::DURATION_INTERVAL_REGEX,
        message: N_('Must be in the following format: `30m`, `2h`, or `1d`')
      }
      validates :zoekt_lost_node_threshold, format: {
        with: ::Search::Zoekt::Settings::DURATION_INTERVAL_REGEX,
        message: N_('Must be in the following format: `30m`, `2h`, or `1d`')
      }

      validates :code_creation, json_schema: { filename: 'application_setting_code_creation' }

      with_options(inclusion: { in: [true, false], message: N_('must be a boolean value') }) do
        validates(
          :dashboard_limit_enabled,
          :security_policy_global_group_approvers_enabled,
          :allow_account_deletion,
          :instance_level_ai_beta_features_enabled,
          :observability_backend_ssl_verification_enabled,
          :auto_duo_code_review_enabled,
          :auto_duo_code_review_on_push_enabled,
          :duo_code_review_decisions_enabled,
          :duo_code_review_approval_counts_enabled,
          :duo_remote_flows_enabled,
          :duo_foundational_flows_enabled,
          :duo_custom_agents_enabled,
          :duo_custom_flows_enabled,
          :display_gitlab_credits_user_data,
          :duo_code_review_depth_allowed
        )
      end

      validates :duo_scheduled_triggers_enabled,
        inclusion: { in: [true, false], message: N_('must be a boolean value') },
        if: -> { respond_to?(:duo_scheduled_triggers_enabled) }

      validate :duo_settings_immutable_on_saas,
        on: :update,
        if: -> { ::Gitlab::Saas.feature_available?(:gitlab_duo_saas_only) }

      validate :built_in_project_templates_enabled_immutable_on_saas,
        on: :update,
        if: -> { ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) }

      validates :ci_cd_catalog_projects_allowlist, length: { maximum: 1_000 }

      after_commit :update_personal_access_tokens_lifetime, if: :saved_change_to_max_personal_access_token_lifetime?
      after_commit :schedule_secret_push_protection_analyzer_status_update,
        if: :secret_push_protection_settings_changed?
      after_commit :trigger_clickhouse_for_analytics_enabled_event
      after_commit :remove_code_data_from_elasticsearch, if: :elasticsearch_code_scope_opted_out?
      after_commit :schedule_orbit_auto_index, on: :update, if: :orbit_auto_index_root_namespace_just_enabled?
      after_commit :track_restricted_access_disabled_self_managed, on: :update,
        if: :restricted_access_disabled_self_managed?
      after_commit :track_restricted_access_enabled_self_managed, on: :update,
        if: :restricted_access_enabled_self_managed?
    end

    def tool_approval_for_session_availability
      Ai::ToolApprovalHelper.to_session_availability(
        tool_approval_for_session_enabled,
        lock_tool_approval_for_session_enabled
      )
    end

    def tool_approval_for_session_availability=(value)
      self.tool_approval_for_session_enabled = Ai::ToolApprovalHelper.enabled_for_session_availability(value)
      self.lock_tool_approval_for_session_enabled = Ai::ToolApprovalHelper.locked_for_session_availability(value)
    end

    def duo_auto_mode_availability
      Ai::ToolApprovalHelper.to_session_availability(
        duo_auto_mode_enabled,
        lock_duo_auto_mode_enabled
      )
    end

    def duo_auto_mode_availability=(value)
      self.duo_auto_mode_enabled = Ai::ToolApprovalHelper.enabled_for_session_availability(value)
      self.lock_duo_auto_mode_enabled = Ai::ToolApprovalHelper.locked_for_session_availability(value)
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      override :defaults
      def defaults
        super.merge(
          # As an exception, we need Elasticsearch default settings with jsonb accessor
          # because they are needed for the E2E specs, contrary to the docs:
          # https://docs.gitlab.com/development/application_settings/#default-values
          # Please follow https://gitlab.com/gitlab-org/gitlab/-/issues/553575 for updates
          jsonb_defaults_mapping_for_elasticsearch.transform_keys(&:to_sym)
        ).merge(
          ai_gateway_url: ENV['AI_GATEWAY_URL'],
          allow_group_owners_to_manage_ldap: true,
          automatic_purchased_storage_allocation: false,
          ci_cd_catalog_projects_allowlist: [],
          custom_project_templates_group_id: nil,
          dashboard_limit_enabled: false,
          dashboard_limit: 0,
          default_project_deletion_protection: false,
          disable_personal_access_tokens: false,
          elasticsearch_url: ENV['ELASTIC_URL'] || 'http://localhost:9200',
          email_additional_text: nil,
          enabled_instance_verbose_ai_logs: false,
          enforce_namespace_storage_limit: false,
          future_subscriptions: [],
          geo_node_allowed_ips: '0.0.0.0/0, ::/0',
          git_two_factor_session_expiry: 15,
          globally_allowed_ips: '',
          license_usage_data_exported: false,
          lock_memberships_to_ldap: false,
          lock_memberships_to_saml: false,
          maintenance_mode: false,
          max_personal_access_token_lifetime: nil,
          max_ssh_key_lifetime: nil,
          mirror_capacity_threshold: Settings.gitlab['mirror_capacity_threshold'],
          mirror_max_capacity: Settings.gitlab['mirror_max_capacity'],
          mirror_max_delay: Settings.gitlab['mirror_max_delay'],
          repository_size_limit: 0,
          secret_detection_token_revocation_enabled: false,
          secret_detection_token_revocation_url: nil,
          secret_detection_token_revocation_token: nil,
          secret_detection_revocation_token_types_url: nil,
          max_number_of_repository_downloads: 0,
          max_number_of_repository_downloads_within_time_period: 0,
          git_rate_limit_users_allowlist: [],
          git_rate_limit_users_alertlist: [],
          auto_ban_user_on_excessive_projects_download: false,
          product_analytics_enabled: false,
          product_analytics_data_collector_host: nil,
          product_analytics_configurator_connection_string: nil,
          cube_api_base_url: nil,
          cube_api_key: nil,
          secret_detection_service_url: '',
          secret_detection_service_auth_token: nil
        )
      end

      override :rate_limits_definition
      def rate_limits_definition
        super.merge(
          audit_events_api_limit: [:integer, { default: 200 }],
          project_audit_events_api_limit: [:integer, { default: 200 }],
          group_audit_events_api_limit: [:integer, { default: 200 }],
          dependency_scanning_sbom_scan_api_upload_limit: [:integer, { default: 400 }],
          dependency_scanning_sbom_scan_api_download_limit: [:integer, { default: 6000 }],
          virtual_registries_endpoints_api_limit: [:integer, { default: 4000 }],
          epic_move_list_limit: [:integer, { default: 200 }],
          insights_query_limit: [:integer, { default: 0 }],
          merge_train_removal_limit_per_user: [:integer, { default: 30 }],
          orbit_query_limit: [:integer, { default: 60 }],
          orbit_indexing_status_limit: [:integer, { default: 30 }],
          orbit_item_counts_limit: [:integer, { default: 30 }],
          orbit_rate_limit_allowlist: [:string, { array: true, default: [] }],
          service_desk_paid_namespace_probation_days: [:integer, { default: 7 }],
          subscription_usage_per_minute_limit: [:integer, { default: 300 }],
          subscription_usage_per_hour_limit: [:integer, { default: 10_000 }],
          subscription_usage_per_day_limit: [:integer, { default: 40_000 }],
          budget_cap_update_per_minute_limit: [:integer, { default: 150 }],
          budget_cap_update_per_hour_limit: [:integer, { default: 1_000 }],
          budget_cap_update_per_day_limit: [:integer, { default: 20_000 }],
          credits_usage_per_minute_limit: [:integer, { default: 60 }],
          credits_usage_per_hour_limit: [:integer, { default: 300 }],
          credits_usage_per_day_limit: [:integer, { default: 3_000 }]
        )
      end

      override :ci_cd_settings_definition
      def ci_cd_settings_definition
        super.merge(
          ci_cd_catalog_projects_allowlist: [:string, { array: true, default: [] }],
          ci_telemetry_otel_endpoint: [:string, { default: nil }],
          ci_job_telemetry_sampling_rate: [:float, { default: 0.0 }]
        )
      end
    end

    def block_jwt_for_reclaimed_paths
      return true if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      super
    end

    def instance_built_in_project_templates_enabled_available?
      !::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) &&
        ::License.feature_available?(:built_in_project_templates_enabled)
    end

    def allow_instance_built_in_project_templates?
      return true unless instance_built_in_project_templates_enabled_available?

      built_in_project_templates_enabled
    end

    def duo_template_project_available?
      # Instance-wide Duo template is not available on SaaS
      return false if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      ::License.ai_features_available?
    end

    def dependency_firewall_setting_available?
      ::Security::DependencyFirewall::Availability.instance_configurable?
    end

    def allowed_integrations_raw=(value)
      self.allowed_integrations = ::Gitlab::Json.safe_parse(value)
    end

    def max_auth_lifetime
      if ::Feature.enabled?(:buffered_token_expiration_limit)
        400
      else
        365
      end
    end

    def elasticsearch_namespace_ids
      ElasticsearchIndexedNamespace.target_ids
    end

    def elasticsearch_project_ids
      ElasticsearchIndexedProject.target_ids
    end

    def elasticsearch_shards
      Elastic::IndexSetting.number_of_shards
    end

    def elasticsearch_replicas
      Elastic::IndexSetting.number_of_replicas
    end

    def elasticsearch_index_settings
      Elastic::IndexSetting.order_by_name
    end

    def elasticsearch_indexes_project?(project)
      return false unless elasticsearch_indexing?
      return true unless elasticsearch_limit_indexing?

      ::Search::Elastic::ElasticsearchEnabledCache.fetch(:project, project.id) do
        elasticsearch_limited_project_exists?(project)
      end
    end

    def elasticsearch_indexes_namespace?(namespace)
      return false unless elasticsearch_indexing?
      return true unless elasticsearch_limit_indexing?

      ::Search::Elastic::ElasticsearchEnabledCache.fetch(:namespace, namespace.id) do
        # traversal_ids is still empty while a namespace's own after_create_commit
        # callbacks run, so resolve ancestry from the database rather than matching [],
        # which would cache a false negative and skip indexing the new namespace.
        ancestor_ids = namespace.traversal_ids.presence || namespace.self_and_ancestor_ids

        ElasticsearchIndexedNamespace.where(namespace_id: ancestor_ids).exists?
      end
    end

    def invalidate_elasticsearch_indexes_cache!
      ::Search::Elastic::ElasticsearchEnabledCache.delete(:project)
      ::Search::Elastic::ElasticsearchEnabledCache.delete(:namespace)
    end

    def invalidate_elasticsearch_indexes_cache_for_project!(project_id)
      ::Search::Elastic::ElasticsearchEnabledCache.delete_record(:project, project_id)
    end

    def invalidate_elasticsearch_indexes_cache_for_namespace!(namespace_id)
      ::Search::Elastic::ElasticsearchEnabledCache.delete_record(:namespace, namespace_id)
    end

    def elasticsearch_limited_projects(ignore_namespaces = false)
      return ::Project.where(id: ElasticsearchIndexedProject.select(:project_id)) if ignore_namespaces

      union = ::Gitlab::SQL::Union.new([
        ::Project.where(namespace_id: elasticsearch_limited_namespaces.select(:id)),
        ::Project.where(id: ElasticsearchIndexedProject.select(:project_id))
      ]).to_sql

      ::Project.from("(#{union}) projects")
    end

    def elasticsearch_limited_namespaces(ignore_descendants = false)
      namespaces = ::Namespace.where(id: ElasticsearchIndexedNamespace.select(:namespace_id))

      return namespaces if ignore_descendants

      namespaces.self_and_descendants
    end

    def elasticsearch_enabled_groups
      return ::Group.all unless elasticsearch_limit_indexing?

      ::Group.id_in(elasticsearch_limited_namespaces.select(:id)).self_and_descendants
    end

    def elasticsearch_enabled_projects
      return ::Project.all unless elasticsearch_limit_indexing?

      elasticsearch_limited_projects
    end

    def should_check_namespace_plan?
      check_namespace_plan? && (Rails.env.test? || ::Gitlab.org_or_com?) # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- pre-existing code, not introduced by this MR
    end

    def elasticsearch_indexing
      super && License.feature_available?(:elastic_search) # rubocop:disable Gitlab/LicenseAvailableUsage -- Does not have cyclical dependency
    end
    alias_method :elasticsearch_indexing?, :elasticsearch_indexing

    def elasticsearch_search
      super && License.feature_available?(:elastic_search) # rubocop:disable Gitlab/LicenseAvailableUsage -- Does not have cyclical dependency
    end
    alias_method :elasticsearch_search?, :elasticsearch_search

    # Determines whether a search should use elasticsearch, taking the scope
    # (nil for global search, otherwise a namespace or project) into account
    def search_using_elasticsearch?(scope: nil)
      return false unless elasticsearch_indexing? && elasticsearch_search?
      return true unless elasticsearch_limit_indexing?

      case scope
      when Namespace
        elasticsearch_indexes_namespace?(scope)
      when Project
        elasticsearch_indexes_project?(scope)
      else
        ::Gitlab::CurrentSettings.global_search_limited_indexing_enabled?
      end
    end

    def elasticsearch_url
      read_attribute(:elasticsearch_url).split(',').map do |s|
        URI.parse(s.strip)
      end
    end

    def elasticsearch_url=(values)
      urls = case values
             when String
               values.split(',')
             when Array
               values.flat_map { |v| v.to_s.split(',') }
             else
               []
             end

      cleaned = urls.map { |url| url.strip.gsub(%r{/*\z}, '') }.reject(&:blank?)

      write_attribute(:elasticsearch_url, cleaned.join(','))
    end

    def elasticsearch_password=(value)
      return if value == MASK_PASSWORD

      super
    end

    def elasticsearch_aws_secret_access_key=(value)
      return if value == MASK_PASSWORD

      super
    end

    def elasticsearch_url_with_credentials
      ::EE::Search::ElasticsearchUrl.with_credentials(
        read_attribute(:elasticsearch_url),
        username: elasticsearch_username,
        password: elasticsearch_password
      )
    end

    def elasticsearch_config
      configured_timeout = Rails.env.test? ? ELASTIC_REQUEST_TIMEOUT : elasticsearch_client_request_timeout
      client_request_timeout = configured_timeout.to_i > 0 ? configured_timeout : ELASTIC_REQUEST_TIMEOUT

      {
        url: elasticsearch_url_with_credentials,
        aws: elasticsearch_aws,
        aws_access_key: elasticsearch_aws_access_key,
        aws_secret_access_key: elasticsearch_aws_secret_access_key,
        aws_region: elasticsearch_aws_region,
        aws_role_arn: elasticsearch_aws_role_arn,
        client_adapter: elasticsearch_client_adapter,
        max_bulk_size_bytes: elasticsearch_max_bulk_size_mb.megabytes,
        max_bulk_concurrency: elasticsearch_max_bulk_concurrency,
        client_request_timeout: client_request_timeout
      }.compact
    end

    def active_context_indexing_paused?
      elasticsearch_pause_indexing || active_context_pause_indexing
    end

    def advanced_search_indexing_paused?
      elasticsearch_pause_indexing || elasticsearch_advanced_search_pause_indexing
    end

    def email_additional_text_character_limit
      EMAIL_ADDITIONAL_TEXT_CHARACTER_LIMIT
    end

    def custom_project_templates_enabled?
      License.feature_available?(:custom_project_templates) # rubocop:disable Gitlab/LicenseAvailableUsage -- Does not have cyclical dependency
    end

    def custom_project_templates_group_id
      super if super.present? && custom_project_templates_enabled?
    end

    def available_custom_project_templates(subgroup_id = nil)
      group_id = subgroup_id || custom_project_templates_group_id

      return ::Project.none unless group_id

      ::Project.where(namespace_id: group_id)
    end

    override :instance_review_permitted?
    def instance_review_permitted?
      return false if License.current

      super
    end

    def max_personal_access_token_lifetime_from_now
      return unless max_personal_access_token_lifetime

      Date.current + max_personal_access_token_lifetime
    end

    def max_ssh_key_lifetime_from_now
      max_ssh_key_lifetime&.days&.from_now
    end

    def compliance_frameworks=(values)
      cleaned = Array.wrap(values).reject(&:blank?).sort.uniq

      write_attribute(:compliance_frameworks, cleaned)
    end

    def lock_memberships_to_ldap_or_saml?
      lock_memberships_to_ldap? || lock_memberships_to_saml?
    end

    override :personal_access_tokens_disabled?
    def personal_access_tokens_disabled?
      ::Gitlab::CurrentSettings.disable_personal_access_tokens &&
        License.feature_available?(:disable_personal_access_tokens) # rubocop:disable Gitlab/LicenseAvailableUsage -- Does not have cyclical dependency as it's not used in Registration features
    end

    def disable_feed_token
      personal_access_tokens_disabled? || read_attribute(:disable_feed_token)
    end
    alias_method :disable_feed_token?, :disable_feed_token

    def normalize_duo_workflows_default_image_registry
      self.duo_workflows_default_image_registry = nil if duo_workflows_default_image_registry.blank?
    end

    def normalize_ci_telemetry_otel_endpoint
      self.ci_telemetry_otel_endpoint = ci_telemetry_otel_endpoint.presence
    end

    def git_rate_limit_users_alertlist
      (self[:git_rate_limit_users_alertlist].presence || ::User.admins.active.pluck_primary_key).sort
    end

    def package_metadata_purl_types_names
      ::Enums::Sbom.purl_types_numerical.values_at(*package_metadata_purl_types)
    end

    def unique_project_download_limit_enabled?
      if max_number_of_repository_downloads.nonzero? && max_number_of_repository_downloads_within_time_period.nonzero?
        return true
      end

      false
    end

    def duo_availability
      if duo_features_enabled && lock_duo_features_enabled
        :always_on
      elsif duo_features_enabled && !lock_duo_features_enabled
        :default_on
      elsif !duo_features_enabled && !lock_duo_features_enabled
        :default_off
      else
        :never_on
      end
    end

    def duo_availability=(value)
      case value
      when "always_on"
        self.duo_features_enabled = true
        self.lock_duo_features_enabled = true
      when "default_on"
        self.duo_features_enabled = true
        self.lock_duo_features_enabled = false
      when "default_off"
        self.duo_features_enabled = false
        self.lock_duo_features_enabled = false
      else
        self.duo_features_enabled = false
        self.lock_duo_features_enabled = true
        self.instance_level_ai_beta_features_enabled = false
      end
    end

    def duo_remote_flows_availability
      duo_remote_flows_enabled
    end

    def duo_remote_flows_availability=(value)
      self.duo_remote_flows_enabled = value

      self.lock_duo_remote_flows_enabled = if value
                                             false
                                           else
                                             true
                                           end
    end

    def duo_foundational_flows_availability
      duo_foundational_flows_enabled
    end

    def duo_foundational_flows_availability=(value)
      self.duo_foundational_flows_enabled = value

      self.lock_duo_foundational_flows_enabled = if value
                                                   false
                                                 else
                                                   true
                                                 end
    end

    # The API and the admin form call this setting "scheduled automations". The columns keep
    # the older duo_scheduled_triggers_* names, so these read and write through to them.
    def duo_scheduled_automations_enabled
      duo_scheduled_triggers_enabled
    end

    def duo_scheduled_automations_enabled=(value)
      self.duo_scheduled_triggers_enabled = value
    end

    def lock_duo_scheduled_automations_enabled
      lock_duo_scheduled_triggers_enabled
    end

    def lock_duo_scheduled_automations_enabled=(value)
      self.lock_duo_scheduled_triggers_enabled = value
    end

    def duo_scheduled_automations_availability
      duo_scheduled_triggers_enabled
    end

    def duo_scheduled_automations_availability=(value)
      self.duo_scheduled_triggers_enabled = value

      self.lock_duo_scheduled_triggers_enabled = !value
    end

    def duo_custom_agents_availability
      duo_custom_agents_enabled
    end

    def duo_custom_agents_availability=(value)
      self.duo_custom_agents_enabled = value

      self.lock_duo_custom_agents_enabled = if value
                                              false
                                            else
                                              true
                                            end
    end

    def duo_custom_flows_availability
      duo_custom_flows_enabled
    end

    def duo_custom_flows_availability=(value)
      self.duo_custom_flows_enabled = value

      self.lock_duo_custom_flows_enabled = if value
                                             false
                                           else
                                             true
                                           end
    end

    def duo_external_agents_availability
      duo_external_agents_enabled
    end

    def duo_external_agents_availability=(value)
      self.duo_external_agents_enabled = value
      self.lock_duo_external_agents_enabled = !value
    end

    def duo_never_on?
      duo_availability == :never_on
    end

    def enabled_expanded_logging
      enabled_instance_verbose_ai_logs
    end

    def enabled_expanded_logging=(value)
      self.enabled_instance_verbose_ai_logs = value
    end

    def foundational_agents_default_enabled
      ::Ai::Setting.for_organization_read_only(default_organization).foundational_agents_default_enabled
    end

    def foundational_agents_default_enabled=(value)
      ::Ai::Setting.for_organization(default_organization).update!(foundational_agents_default_enabled: value)
    end

    def foundational_agents_statuses
      default_organization.foundational_agents_statuses
    end

    def foundational_agents_statuses=(value)
      default_organization.update!(foundational_agents_statuses: value)
    end

    def duo_namespace_access_rules
      ::Ai::FeatureAccessRule.duo_namespace_access_rules
    end

    def duo_agent_platform_enabled
      ::Ai::Setting.for_organization_read_only(default_organization).duo_agent_platform_enabled
    end

    def duo_agent_platform_enabled=(value)
      ::Ai::Setting.for_organization(default_organization).update!(duo_agent_platform_enabled: value)
    end

    def duo_cli_enabled
      ::Ai::Setting.for_organization_read_only(default_organization).duo_cli_enabled
    end

    def duo_cli_enabled=(value)
      ::Ai::Setting.for_organization(default_organization).update!(duo_cli_enabled: value)
    end

    def ai_audit_events_streaming_enabled
      ::Ai::Setting.for_organization_read_only(default_organization).ai_audit_events_streaming_enabled
    end

    def ai_audit_events_streaming_enabled=(value)
      ::Ai::Setting.for_organization(default_organization).update!(ai_audit_events_streaming_enabled: value)
    end

    def duo_token_usage_tracking_enabled
      ::Ai::Setting.for_organization_read_only(default_organization).duo_token_usage_tracking_enabled
    end

    def duo_token_usage_tracking_enabled=(value)
      ::Ai::Setting.for_organization(default_organization).update!(duo_token_usage_tracking_enabled: value)
    end

    def duo_workflow_file_attachments_enabled
      ::Ai::Setting.for_organization_read_only(default_organization).duo_workflow_file_attachments_enabled
    end

    def duo_workflow_file_attachments_enabled=(value)
      ::Ai::Setting.for_organization(default_organization).update!(duo_workflow_file_attachments_enabled: value)
    end

    def seat_control_user_cap?
      return false unless License.feature_available?(:seat_control) # rubocop:disable Gitlab/LicenseAvailableUsage -- Does not have cyclical dependency as it's not used for Registration features

      seat_control == SEAT_CONTROL_USER_CAP
    end

    def seat_control_block_overages?
      return false unless License.feature_available?(:seat_control) # rubocop:disable Gitlab/LicenseAvailableUsage -- Does not have cyclical dependency as it's not used for Registration features

      seat_control == SEAT_CONTROL_BLOCK_OVERAGES
    end

    def ci_cd_catalog_projects_allowlist_raw
      array_to_string(ci_cd_catalog_projects_allowlist)
    end

    def ci_cd_catalog_projects_allowlist_raw=(values)
      self.ci_cd_catalog_projects_allowlist = strings_to_array(values)
    end

    def orbit_rate_limit_allowlist_raw
      array_to_string(orbit_rate_limit_allowlist)
    end

    def orbit_rate_limit_allowlist_raw=(values)
      self.orbit_rate_limit_allowlist = strings_to_array(values)
    end

    def vac_project_ids_raw
      array_to_string(vac_project_ids)
    end

    def vac_project_ids_raw=(values)
      self.vac_project_ids = strings_to_array(values).map(&:to_i).reject(&:zero?)
    end

    def sms_cost_restricted_dial_codes_raw
      array_to_string(sms_cost_restricted_dial_codes)
    end

    def sms_cost_restricted_dial_codes_raw=(values)
      self.sms_cost_restricted_dial_codes = strings_to_array(values).map(&:to_i)
    end

    def security_mr_report_cache_lifetime_minutes
      super || SECURITY_MR_REPORT_CACHE_LIFETIME_MINUTES_DEFAULT
    end

    # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- conditional default based on deployment type
    def security_scan_stale_after_days
      super || if ::Gitlab.com?
                 SECURITY_SCAN_STALE_AFTER_DAYS_DEFAULT_GITLAB_COM
               else
                 SECURITY_SCAN_STALE_AFTER_DAYS_DEFAULT_SELF_MANAGED
               end
    end
    # rubocop:enable Gitlab/AvoidGitlabInstanceChecks

    private

    def default_organization
      # rubocop:disable Gitlab/AvoidDefaultOrganization -- needs to use default organization
      @default_organization ||= ::Organizations::Organization.default_organization ||
        raise('Default organization not found')
      # rubocop:enable Gitlab/AvoidDefaultOrganization
    end

    def elasticsearch_limited_project_exists?(project)
      project_namespaces = ::Namespace.where(id: project.namespace_id)
      self_and_ancestors_namespaces = project_namespaces.self_and_ancestors.joins(:elasticsearch_indexed_namespace)

      indexed_namespaces = ::Project.where('EXISTS (?)', self_and_ancestors_namespaces)
      indexed_projects = ::Project.where('EXISTS (?)', ElasticsearchIndexedProject.where(project_id: project.id))

      ::Project
        .from("(SELECT) as projects") # SELECT from "nothing" since the EXISTS queries have all the conditions.
        .merge(indexed_namespaces.or(indexed_projects))
        .exists?
    end

    def update_personal_access_tokens_lifetime
      return unless max_personal_access_token_lifetime.present? && License.feature_available?(:personal_access_token_expiration_policy) # rubocop:disable Gitlab/LicenseAvailableUsage -- Does not have cyclical dependency as it's not used for Registration features

      ::PersonalAccessTokens::Instance::UpdateLifetimeService.new.execute
    end

    def mirror_max_delay_in_minutes
      ::Gitlab::Mirror.min_delay_upper_bound / 60
    end

    def mirror_capacity_threshold_less_than
      return unless mirror_max_capacity && mirror_capacity_threshold

      return unless mirror_capacity_threshold > mirror_max_capacity

      errors.add(:mirror_capacity_threshold,
        "Project's mirror capacity threshold can't be higher than it's maximum capacity")
    end

    def check_geo_node_allowed_ips
      ::Gitlab::CIDR.new(geo_node_allowed_ips)
    rescue ::Gitlab::CIDR::ValidationError => e
      errors.add(:geo_node_allowed_ips, e.message)
    end

    def check_globally_allowed_ips
      ::Gitlab::CIDR.new(globally_allowed_ips)
    rescue ::Gitlab::CIDR::ValidationError => e
      errors.add(:globally_allowed_ips, e.message)
    end

    def elasticsearch_prefix_no_whitespace
      return unless elasticsearch_prefix
      return unless elasticsearch_prefix != elasticsearch_prefix.strip

      errors.add(:elasticsearch_prefix, 'cannot contain leading or trailing whitespace')
    end

    def check_elasticsearch_url_scheme
      ::EE::Search::ElasticsearchUrl.validate!(
        elasticsearch_url,
        deny_all_requests_except_allowed: deny_all_requests_except_allowed,
        outbound_local_requests_allowlist: outbound_local_requests_whitelist # rubocop:disable Naming/InclusiveLanguage -- existing setting
      )
    rescue ::Gitlab::HTTP_V2::UrlBlocker::BlockedUrlError
      errors.add(:elasticsearch_url, "only supports valid HTTP(S) URLs.")
    end

    def check_allowed_integrations
      unknown_integrations = allowed_integrations - ::Integration.all_integration_names

      return if unknown_integrations.blank?

      errors.add(:allowed_integrations, 'contains unknown integration names')
    end

    def trigger_clickhouse_for_analytics_enabled_event
      return if !saved_change_to_use_clickhouse_for_analytics? || !use_clickhouse_for_analytics?

      ::Gitlab::EventStore.publish(
        ::Analytics::ClickHouseForAnalyticsEnabledEvent.new(data: { enabled_at: updated_at.iso8601 })
      )
    end

    def duo_settings_immutable_on_saas
      unless duo_features_enabled_changed? || lock_duo_features_enabled_changed? ||
          duo_remote_flows_enabled_changed? || ai_agent_governance_enforcement_changed? ||
          lock_ai_agent_governance_enforcement_changed? || duo_scheduled_triggers_enabled_changed? ||
          lock_duo_scheduled_triggers_enabled_changed?
        return
      end

      errors.add(:base, 'Duo settings cannot be modified on GitLab.com')
    end

    def built_in_project_templates_enabled_immutable_on_saas
      return unless built_in_project_templates_enabled_changed? || lock_built_in_project_templates_enabled_changed?

      errors.add(:base, 'Built-in project templates enabled cannot be modified on GitLab.com')
    end

    def remove_code_data_from_elasticsearch
      ::Search::Elastic::DeleteWorker.perform_async('task' => 'delete_all_blobs')
    end

    def orbit_auto_index_root_namespace_just_enabled?
      saved_change_to_orbit_auto_index_root_namespace? && orbit_auto_index_root_namespace?
    end

    def schedule_orbit_auto_index
      ::Analytics::KnowledgeGraph::AutoIndexWorker.perform_async
    end

    def elasticsearch_code_scope_opted_out?
      elasticsearch_code_scope_previously_changed?(from: true, to: false)
    end

    def restricted_access_disabled_self_managed?
      saved_change_to_seat_control? && seat_control == SEAT_CONTROL_OFF
    end

    def restricted_access_enabled_self_managed?
      saved_change_to_seat_control? && seat_control == SEAT_CONTROL_BLOCK_OVERAGES
    end

    def track_restricted_access_disabled_self_managed
      ::Gitlab::InternalEvents.track_event(
        'restricted_access_disabled',
        additional_properties: restricted_access_self_managed_properties
      )
    end

    def track_restricted_access_enabled_self_managed
      ::Gitlab::InternalEvents.track_event(
        'restricted_access_enabled',
        additional_properties: restricted_access_self_managed_properties
      )
    end

    def restricted_access_self_managed_properties
      {
        seat_count: License.current.seats
      }
    end

    def set_secret_push_protection_from_mode
      return unless secret_push_protection_mode.present?

      self.secret_push_protection_available = secret_push_protection_mode != 'disabled'
      self.secret_push_protection_enforced  = secret_push_protection_mode == 'enforced'
    end

    def secret_push_protection_settings_changed?
      secret_push_protection_available_previously_changed? ||
        secret_push_protection_enforced_previously_changed?
    end

    def schedule_secret_push_protection_analyzer_status_update
      ::Security::AnalyzersStatus::ScheduleInstanceSettingChangedUpdateWorker
        .perform_async('secret_detection')
    end

    def validate_ai_gateway_url
      validate_ai_url_attribute(
        attribute: :ai_gateway_url,
        value: ai_gateway_url
      )
    end

    def validate_ai_url_attribute(attribute:, value:)
      return if value.blank?

      begin
        ::Gitlab::HTTP_V2::UrlBlocker.validate!(
          value,
          schemes: %w[http https],
          allow_localhost: allow_ai_url_localhost,
          enforce_sanitization: true,
          deny_all_requests_except_allowed: deny_all_requests_except_allowed?,
          outbound_local_requests_allowlist: outbound_local_requests_whitelist # rubocop:disable Naming/InclusiveLanguage -- existing setting
        )
      rescue ::Gitlab::HTTP_V2::UrlBlocker::BlockedUrlError => e
        errors.add(attribute, e.message)
      end
    end

    def allow_ai_url_localhost
      return true if ::Gitlab.dev_or_test_env?

      false
    end
  end
end
