# frozen_string_literal: true

module EE
  module API
    module Helpers
      module SettingsHelpers
        extend ActiveSupport::Concern

        prepended do
          params :optional_params_ee do
            optional :elasticsearch_aws, type: Grape::API::Boolean, desc: 'If `true`, enables the use of AWS hosted Elasticsearch. Premium and Ultimate only.'

            given elasticsearch_aws: ->(val) { val } do
              optional :elasticsearch_aws_access_key, type: String, desc: 'AWS IAM access key. Premium and Ultimate only.'
              requires :elasticsearch_aws_region, type: String, desc: 'AWS region where the Elasticsearch domain is configured. Premium and Ultimate only.'
              optional :elasticsearch_aws_secret_access_key, type: String, desc: 'AWS IAM secret access key. Premium and Ultimate only.'
            end

            optional :elasticsearch_indexing, type: Grape::API::Boolean, desc: 'If `true`, turns on indexing for advanced search. Premium and Ultimate only.'

            given elasticsearch_indexing: ->(val) { val } do
              optional :elasticsearch_search, type: Grape::API::Boolean, desc: 'If `true`, enables Elasticsearch search. Premium and Ultimate only.'
              optional :elasticsearch_pause_indexing, type: Grape::API::Boolean, desc: 'If `true`, pauses Elasticsearch indexing for both Advanced Search and ActiveContext.'
              optional :elasticsearch_advanced_search_pause_indexing, type: Grape::API::Boolean, desc: 'If `true`, pauses advanced search indexing.'
              requires :elasticsearch_url, type: String, desc: 'URL to use for connecting to Elasticsearch. Use a comma-separated list or an array to support clustering (for example, `http://localhost:9200, http://localhost:9201` or `["http://localhost:9200", "http://localhost:9201"]`). Premium and Ultimate only.'
              optional :elasticsearch_username, type: String, desc: 'Username of your Elasticsearch instance. Premium and Ultimate only.'
              optional :elasticsearch_password, type: String, desc: 'Password of your Elasticsearch instance. Premium and Ultimate only.'
              optional :elasticsearch_limit_indexing, type: Grape::API::Boolean, desc: 'If `true`, limits Elasticsearch to index certain namespaces and projects. Premium and Ultimate only.'
            end

            optional :active_context_pause_indexing, type: Grape::API::Boolean, desc: 'If `true`, pauses ActiveContext indexing.'

            given elasticsearch_limit_indexing: ->(val) { val } do
              optional :elasticsearch_namespace_ids, type: Array[Integer], coerce_with: ::API::Validations::Types::CommaSeparatedToIntegerArray.coerce, desc: 'IDs of namespaces to index with Elasticsearch if `elasticsearch_limit_indexing` is enabled. Premium and Ultimate only.'
              optional :elasticsearch_project_ids, type: Array[Integer], coerce_with: ::API::Validations::Types::CommaSeparatedToIntegerArray.coerce, desc: 'IDs of projects to index with Elasticsearch if `elasticsearch_limit_indexing` is enabled. Premium and Ultimate only.'
            end

            optional :secret_detection_token_revocation_enabled, type: ::Grape::API::Boolean, desc: 'If `true`, enables secret detection token revocation.'
            # The two URLs below configure the external Token Revocation API, which is only used
            # for third-party secret types. GitLab PAT revocation is handled internally and does
            # not need them, so enabling the setting must not require them.
            optional :secret_detection_token_revocation_url, type: String, desc: 'URL that GitLab sends leaked tokens to for revocation.'
            optional :secret_detection_revocation_token_types_url, type: String, desc: 'URL that returns the token types that can be revoked.'

            optional :email_additional_text, type: String, desc: 'Additional text added to the bottom of every email for legal/auditing/compliance reasons. Premium and Ultimate only.'
            optional :default_project_deletion_protection, type: Grape::API::Boolean, desc: 'If `true`, enables default project deletion protection so only administrators can delete projects. GitLab Self-Managed, Premium and Ultimate only.'
            optional :disable_personal_access_tokens, type: Grape::API::Boolean, desc: "If `true`, disables personal access tokens. GitLab Self-Managed, Premium and Ultimate only. There is no method available to enable a personal access token that's been disabled through the API. This is a [known issue](https://gitlab.com/gitlab-org/gitlab/-/issues/399233). For more information about available workarounds, see [Workaround](https://gitlab.com/gitlab-org/gitlab/-/issues/399233#workaround)."
            optional :repository_size_limit, type: Integer, desc: 'Size limit per repository (MB). Premium and Ultimate only.'
            optional :file_template_project_id, type: Integer, desc: 'ID of the project to load custom file templates from. Premium and Ultimate only.'
            optional :usage_ping_enabled, type: Grape::API::Boolean, desc: 'Every week GitLab will report license usage back to GitLab, Inc.'
            optional :updating_name_disabled_for_users, type: Grape::API::Boolean, desc: 'If `true`, prevents users from updating their profile name.'
            optional :disable_overriding_approvers_per_merge_request, type: Grape::API::Boolean, desc: 'If `true`, prevents users from overriding approval rules in projects and merge requests.'
            optional :prevent_merge_requests_author_approval, type: Grape::API::Boolean, desc: 'If `true`, prevents merge request authors from approving their own merge requests.'
            optional :prevent_merge_requests_committers_approval, type: Grape::API::Boolean, desc: 'If `true`, prevents committers from approving merge requests they contributed to.'
            optional :maven_package_requests_forwarding, type: Grape::API::Boolean, desc: 'If `true`, forwards Maven package requests to `repo.maven.apache.org` when not found in the GitLab package registry. Premium and Ultimate only.'
            optional :npm_package_requests_forwarding, type: Grape::API::Boolean, desc: 'If `true`, forwards npm package requests to `npmjs.org` when not found in the GitLab package registry. Premium and Ultimate only.'
            optional :pypi_package_requests_forwarding, type: Grape::API::Boolean, desc: 'If `true`, forwards PyPI package requests to `pypi.org` when not found in the GitLab package registry. Premium and Ultimate only.'
            optional :rubygems_package_requests_forwarding, type: Grape::API::Boolean, desc: 'If `true`, forwards RubyGems package requests to `rubygems.org` when not found in the GitLab package registry. Premium and Ultimate only.'
            optional :virtual_registries_endpoints_api_limit, type: Integer, desc: 'Maximum number of requests on virtual registries endpoints, per IP address, per 15 seconds. Default: 4000. To disable limits, set to `0`. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/issues/521692) in GitLab 17.11.'
            optional :audit_events_api_limit, type: Integer, desc: 'Maximum number of requests per minute per user to the instance audit events API.'
            optional :project_audit_events_api_limit, type: Integer, desc: 'Maximum number of requests per minute per user per project to the project audit events API.'
            optional :group_audit_events_api_limit, type: Integer, desc: 'Maximum number of requests per minute per user per group to the group audit events API.'
            optional :insights_query_limit, type: Integer, desc: 'Maximum number of Insights chart queries per minute for each user or IP address, for each group or project. Default: `0`, which disables the rate limit. GitLab.com uses `60`.'
            optional :merge_train_removal_limit_per_user, type: Integer, desc: 'Maximum number of merge requests a user can remove from merge trains per minute. Default: `30`. Set to `0` to disable the rate limit.'
            optional :orbit_query_limit, type: Integer, desc: 'Maximum number of GitLab Orbit queries per minute per user. Default: `60`. Set to `0` to disable the rate limit.'
            optional :orbit_indexing_status_limit, type: Integer, desc: 'Maximum number of GitLab Orbit indexing status requests per minute per user. Default: `30`. Set to `0` to disable the rate limit.'
            optional :orbit_item_counts_limit, type: Integer, desc: 'Maximum number of GitLab Orbit item count requests per minute per user. Default: `30`. Set to `0` to disable the rate limit.'
            optional :orbit_rate_limit_allowlist_raw, type: String, desc: 'Raw newline-, comma-, or whitespace-separated list of usernames excluded from the GitLab Orbit rate limits. Maximum: 100 usernames.'
            optional :subscription_usage_per_minute_limit, type: Integer, desc: 'Maximum number of `subscriptionUsage` and `trialUsage` GraphQL requests per minute per user. Default: `300`. Set to `0` to disable the rate limit.'
            optional :subscription_usage_per_hour_limit, type: Integer, desc: 'Maximum number of `subscriptionUsage` and `trialUsage` GraphQL requests per hour per user. Default: `10000`. Set to `0` to disable the rate limit.'
            optional :subscription_usage_per_day_limit, type: Integer, desc: 'Maximum number of `subscriptionUsage` and `trialUsage` GraphQL requests per day per user. Default: `40000`. Set to `0` to disable the rate limit.'
            optional :budget_cap_update_per_minute_limit, type: Integer, desc: 'Maximum number of `upsertUserBudgetCapOverrides` and `upsertFlatUserCap` GraphQL mutation calls per minute per user. Default: `150`. Set to `0` to disable the rate limit.'
            optional :budget_cap_update_per_hour_limit, type: Integer, desc: 'Maximum number of `upsertUserBudgetCapOverrides` and `upsertFlatUserCap` GraphQL mutation calls per hour per user. Default: `1000`. Set to `0` to disable the rate limit.'
            optional :budget_cap_update_per_day_limit, type: Integer, desc: 'Maximum number of `upsertUserBudgetCapOverrides` and `upsertFlatUserCap` GraphQL mutation calls per day per user. Default: `20000`. Set to `0` to disable the rate limit.'
            optional :credits_usage_per_minute_limit, type: Integer, desc: 'Maximum number of `creditsUsage` GraphQL requests per minute per user. Default: `60`. Set to `0` to disable the rate limit.'
            optional :credits_usage_per_hour_limit, type: Integer, desc: 'Maximum number of `creditsUsage` GraphQL requests per hour per user. Default: `300`. Set to `0` to disable the rate limit.'
            optional :credits_usage_per_day_limit, type: Integer, desc: 'Maximum number of `creditsUsage` GraphQL requests per day per user. Default: `3000`. Set to `0` to disable the rate limit.'
            optional :group_owners_can_manage_default_branch_protection, type: Grape::API::Boolean, desc: 'If `true`, allows group owners to manage default branch protection in their groups. If `false`, group owners cannot override the instance default branch protection. GitLab Self-Managed, Premium and Ultimate only.'
            optional :maintenance_mode, type: Grape::API::Boolean, desc: 'If `true`, puts the instance into maintenance mode. Non-administrator users can sign in with read-only access and make read-only API requests. Premium and Ultimate only.'
            optional :maintenance_mode_message, type: String, desc: 'Message displayed when instance is in maintenance mode. Premium and Ultimate only.'
            optional :git_two_factor_session_expiry, type: Integer, desc: 'Maximum duration (in minutes) of a session for Git operations when 2FA is enabled. Premium and Ultimate only.'
            optional :max_number_of_repository_downloads, type: Integer, desc: 'Maximum number of unique repositories a user can download in the specified time period before they are banned. Default: 0, Maximum: 10,000 repositories. GitLab Self-Managed, Ultimate only.'
            optional :max_number_of_repository_downloads_within_time_period, type: Integer, desc: 'Reporting time period (in seconds). Default: 0, Maximum: 864000 seconds (10 days). GitLab Self-Managed, Ultimate only.'
            optional :git_rate_limit_users_allowlist, type: Array[String], coerce_with: ::API::Validations::Types::CommaSeparatedToArray.coerce, desc: 'List of usernames excluded from Git anti-abuse rate limits. Default: `[]`, Maximum: 100 usernames. GitLab Self-Managed, Ultimate only.'
            optional :git_rate_limit_users_alertlist, type: Array[Integer], desc: 'List of user IDs that are emailed when the Git abuse rate limit is exceeded. Default: `[]`, Maximum: 100 user IDs. GitLab Self-Managed, Ultimate only.'
            optional :auto_ban_user_on_excessive_projects_download, type: Grape::API::Boolean, desc: 'If `true`, automatically bans users from the application when they download more than the maximum number of unique projects in the time period specified by `max_number_of_repository_downloads` and `max_number_of_repository_downloads_within_time_period`. GitLab Self-Managed, Ultimate only.'
            optional :make_profile_private, type: Grape::API::Boolean, desc: 'If `true`, allows users to make their profiles private.'
            optional :service_access_tokens_expiration_enforced, type: Grape::API::Boolean, desc: 'If `true`, enforces token expiration for service account users. Premium and Ultimate only.'
            optional :duo_features_enabled, type: ::Grape::API::Boolean, desc: 'If `true`, enables GitLab Duo features for this instance. GitLab Self-Managed, Premium and Ultimate only.'
            optional :lock_duo_features_enabled, type: ::Grape::API::Boolean, desc: 'If `true`, enforces the GitLab Duo features enabled setting for all subgroups. GitLab Self-Managed, Premium and Ultimate only.'
            optional :disabled_direct_code_suggestions, type: ::Grape::API::Boolean, desc: 'If `true`, disables direct connections for Code Suggestions for users.'
            optional :receptive_cluster_agents_enabled, type: ::Grape::API::Boolean, desc: 'If `true`, enables receptive mode for GitLab agents for Kubernetes.'
            optional :auto_duo_code_review_enabled, type: ::Grape::API::Boolean, desc: 'If `true`, enables automatic reviews by GitLab Duo on merge requests.'
            optional :duo_code_review_decisions_enabled, type: ::Grape::API::Boolean, desc: 'If `true`, GitLab Duo can approve and request changes on merge requests.'
            optional :duo_code_review_depth_allowed, type: ::Grape::API::Boolean, desc: 'If `true`, allows Standard reviews by GitLab Duo Code Review Flow. Beta.'
            optional :duo_code_review_default_depth, type: String, values: ::Gitlab::Duo::CodeReview::DEPTHS, desc: 'Default review depth for GitLab Duo Code Review Flow. One of `lite` or `standard`. Beta.'
            optional :security_scan_stale_after_days, type: Integer, desc: 'Number of days to retain security scan data before purging. Must be between 7 and 90 days. Default: 30 days for GitLab.com, 90 days for GitLab Self-Managed. Premium and Ultimate only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/222998) in GitLab 18.9.'
            optional :duo_custom_agents_enabled, type: ::Grape::API::Boolean, desc: 'If `true`, allows custom agents for this instance. Defaults to `true`. GitLab Self-Managed, Premium and Ultimate only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/594615) in GitLab 19.0.'
            optional :lock_duo_custom_agents_enabled, type: ::Grape::API::Boolean, desc: 'If `true`, enforces the custom agents enabled setting for all groups. GitLab Self-Managed, Premium and Ultimate only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/594615) in GitLab 19.0.'
            optional :duo_custom_flows_enabled, type: ::Grape::API::Boolean, desc: 'If `true`, allows custom flows for this instance. Defaults to `true`. GitLab Self-Managed, Premium and Ultimate only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/594615) in GitLab 19.0.'
            optional :lock_duo_custom_flows_enabled, type: ::Grape::API::Boolean, desc: 'If `true`, enforces the custom flows enabled setting for all groups. GitLab Self-Managed, Premium and Ultimate only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/594615) in GitLab 19.0.'
            optional :duo_external_agents_enabled, type: ::Grape::API::Boolean, desc: 'If `true`, allows external agents for this instance. Defaults to `true`. GitLab Self-Managed, Premium and Ultimate only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/594615) in GitLab 19.0.'
            optional :lock_duo_external_agents_enabled, type: ::Grape::API::Boolean, desc: 'If `true`, enforces the external agents enabled setting for all groups. GitLab Self-Managed, Premium and Ultimate only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/594615) in GitLab 19.0.'
            optional :duo_remote_flows_enabled, type: ::Grape::API::Boolean, desc: 'If `true`, enables GitLab Duo remote flows for the instance.'
            optional :lock_duo_remote_flows_enabled, type: ::Grape::API::Boolean, desc: 'If `true`, enforces the GitLab Duo remote flows enabled setting for all subgroups.'
            optional :duo_scheduled_automations_enabled, type: ::Grape::API::Boolean, desc: 'If `true`, allows GitLab Duo flows to run on a schedule for the instance. Defaults to `true`.'
            optional :lock_duo_scheduled_automations_enabled, type: ::Grape::API::Boolean, desc: 'If `true`, enforces the scheduled automations enabled setting for all groups.'
            optional :duo_workflows_default_image_registry, type: String, desc: 'Default container registry for Duo Agent Platform foundational flow images.'
            optional :ci_telemetry_otel_endpoint, type: String, desc: 'OTEL Collector endpoint URL for CI job telemetry.'
            optional :ci_job_telemetry_sampling_rate, type: Float, desc: 'Sampling rate for CI job telemetry, ranging from 0.0 to 1.0.'
            optional :duo_namespace_access_rules, type: Array, desc: 'Access rules that control which namespaces can access Duo features.' do
              optional :through_namespace, type: Hash, desc: 'Group whose members can access the listed features.' do
                requires :id, type: Integer, desc: 'ID of the group.'
                optional :name, type: String, desc: 'Name of the group.'
                optional :full_path, type: String, desc: 'Full path of the group.'
              end
              requires :features, type: Array[String], desc: 'List of accessible features.', allow_blank: true
            end
            optional :built_in_project_templates_enabled, type: ::Grape::API::Boolean, desc: 'If `true`, enables built-in project templates when users create projects. Premium and Ultimate only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/235284) in GitLab 19.0 [with a feature flag](https://docs.gitlab.com/administration/feature_flags/) named `use_built_in_project_templates_enabled`. [Generally available](https://gitlab.com/gitlab-org/gitlab/-/work_items/593623) in GitLab 19.2. Feature flag `use_built_in_project_templates_enabled` removed.'
            optional :lock_built_in_project_templates_enabled, type: ::Grape::API::Boolean, desc: 'If `true`, enforces the `built_in_project_templates_enabled` setting for all groups. Premium and Ultimate only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/235284) in GitLab 19.0 [with a feature flag](https://docs.gitlab.com/administration/feature_flags/) named `use_built_in_project_templates_enabled`. [Generally available](https://gitlab.com/gitlab-org/gitlab/-/work_items/593623) in GitLab 19.2. Feature flag `use_built_in_project_templates_enabled` removed.'
            optional :duo_template_project_id,
              type: Integer,
              desc: 'ID of the project to use as the Duo Code Review custom instructions template for this instance.'
            optional :use_nats_for_audit_streaming,
              type: ::Grape::API::Boolean,
              desc: 'If `true`, routes audit event streaming through NATS JetStream. NATS must be configured for this setting to take effect. Premium and Ultimate only.'
            # The parameters below are also declared by the `optional_attributes` splat in
            # API::Settings, which cannot carry per-parameter metadata. Descriptions are verbatim
            # from doc/api/settings.md. Only `desc` is set: adding `type` here would make Grape
            # reject values that ActiveRecord currently coerces, which is a breaking change.
            # See https://gitlab.com/gitlab-org/gitlab/-/work_items/612735
            # rubocop:disable API/ParameterType -- types are added in https://gitlab.com/gitlab-org/gitlab/-/work_items/618695
            optional :allow_all_integrations,
              desc: 'If `true`, allows all integrations on the instance. If `false`, only integrations in `allowed_integrations` are allowed. Ultimate only. [Added](https://gitlab.com/gitlab-org/gitlab/-/issues/500610) in GitLab 17.6.'
            optional :allow_group_owners_to_manage_ldap,
              desc: 'If `true`, allows group owners to manage LDAP. Premium and Ultimate only.'
            optional :allowed_integrations,
              desc: 'When `allow_all_integrations` is `false`, only integrations in this list are allowed on the instance. Ultimate only. [Added](https://gitlab.com/gitlab-org/gitlab/-/issues/500610) in GitLab 17.6.'
            optional :automatic_purchased_storage_allocation,
              desc: 'If `true`, permits automatic allocation of purchased storage in a namespace. Relevant only to EE distributions.'
            optional :check_namespace_plan,
              desc: "If `true`, makes licensed EE features available to projects only if the project namespace's plan includes the feature or if the project is public. Premium and Ultimate only."
            optional :delete_unconfirmed_users,
              desc: 'If `true`, deletes users who have not confirmed their email after `unconfirmed_users_delete_after_days` days. Default is `false`. GitLab Self-Managed, Premium and Ultimate only.'
            optional :disable_invite_members, desc: 'If `true`, disables the invite members functionality for groups.'
            optional :elasticsearch_client_adapter,
              desc: 'Faraday adapter used by the Elasticsearch Ruby Client. Defaults to `typhoeus`. Possible values are `typhoeus` and `net_http`. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/issues/550805) in GitLab 18.5. Premium and Ultimate only.'
            optional :elasticsearch_indexed_field_length_limit,
              desc: 'Maximum size of text fields to index by Elasticsearch. A value of `0` means no limit. This does not apply to repository and wiki indexing. Premium and Ultimate only.'
            optional :elasticsearch_indexed_file_size_limit_kb,
              desc: 'Maximum size, in KB, of repository and wiki files that are indexed by Elasticsearch. Premium and Ultimate only.'
            optional :elasticsearch_max_bulk_concurrency,
              desc: 'Maximum concurrency of Elasticsearch bulk requests per indexing operation. This only applies to ' \
                'repository indexing operations. Premium and Ultimate only.'
            optional :elasticsearch_max_bulk_size_mb,
              desc: 'Maximum size of Elasticsearch bulk indexing requests in MB. This only applies to repository ' \
                'indexing operations. Premium and Ultimate only.'
            optional :elasticsearch_max_code_indexing_concurrency,
              desc: 'Maximum concurrency of Elasticsearch code indexing background jobs. This only applies to ' \
                'repository indexing operations. Premium and Ultimate only.'
            optional :elasticsearch_replicas,
              desc: 'Number of replicas for Elasticsearch indices. Use an integer to set all indices to the same value. Use an object to set per-index values. For example: `{"gitlab-production": 1, "gitlab-production-notes": 2}`. When using an object, you must provide both `elasticsearch_shards` and `elasticsearch_replicas` for each index. If either value is missing for an index, that index is skipped. Premium and Ultimate only.'
            optional :elasticsearch_requeue_workers,
              desc: 'If `true`, enables automatic requeuing of indexing workers. This improves non-code indexing throughput by enqueuing Sidekiq jobs until all documents are processed. Premium and Ultimate only.'
            optional :elasticsearch_retry_on_failure,
              desc: 'Maximum number of possible retries for Elasticsearch search requests. Premium and Ultimate ' \
                'only.'
            optional :elasticsearch_shards,
              desc: 'Number of shards for Elasticsearch indices. Use an integer to set all indices to the same value. Use an object to set per-index values. For example: `{"gitlab-production": 5, "gitlab-production-notes": 3}`. When using an object, you must provide both `elasticsearch_shards` and `elasticsearch_replicas` for each index. If either value is missing for an index, that index is skipped. Premium and Ultimate only.'
            optional :elasticsearch_worker_number_of_shards,
              desc: 'Number of indexing worker shards. This improves non-code indexing throughput by enqueuing more ' \
                'parallel Sidekiq jobs. Default is `2`. Premium and Ultimate only.'
            optional :enforce_namespace_storage_limit,
              desc: 'If `true`, enforces namespace storage limits.'
            optional :enforce_pipl_compliance,
              desc: 'If `true`, enforces PIPL compliance on GitLab.com.'
            optional :geo_node_allowed_ips,
              desc: 'Comma-separated list of IPs and CIDRs of allowed secondary nodes. For example, `1.1.1.1, ' \
                '2.2.2.0/24`. GitLab Self-Managed, Premium and Ultimate only.'
            optional :geo_status_timeout,
              desc: 'Number of seconds after which a request to get a secondary node status times out. GitLab Self-Managed, Premium and Ultimate only.'
            optional :globally_allowed_ips,
              desc: 'Comma-separated list of IP addresses and CIDRs always allowed for inbound traffic. For example, ' \
                '`1.1.1.1, 2.2.2.0/24`.'
            optional :group_secrets_limit,
              desc: 'Maximum number of secrets allowed per group in Secrets Manager. Default: 500. To disable the ' \
                'limit, set to `0`. Ultimate only. ' \
                '[Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/219436) in GitLab 18.9.'
            optional :lock_memberships_to_saml, desc: 'If `true`, enforces a [global lock on SAML group memberships](https://docs.gitlab.com/user/group/saml_sso/group_sync/#global-saml-group-memberships-lock).'
            optional :max_personal_access_token_lifetime,
              desc: 'Maximum allowable lifetime for access tokens in days. When left blank, default value of 365 is applied. When set, value must be 365 or less. When changed, existing access tokens with an expiration date beyond the maximum allowable lifetime are revoked. GitLab Self-Managed, Ultimate only. In GitLab 17.6 or later, the maximum lifetime limit can be [extended to 400 days](https://gitlab.com/gitlab-org/gitlab/-/issues/461901) by enabling a [feature flag](https://docs.gitlab.com/administration/feature_flags/) named `buffered_token_expiration_limit`.'
            optional :max_ssh_key_lifetime,
              desc: 'Maximum allowable lifetime for SSH keys in days. GitLab Self-Managed, Ultimate only. In GitLab 17.6 or later, the maximum lifetime limit can be [extended to 400 days](https://gitlab.com/gitlab-org/gitlab/-/issues/461901) by enabling a [feature flag](https://docs.gitlab.com/administration/feature_flags/) named `buffered_token_expiration_limit`.'
            optional :mirror_capacity_threshold,
              desc: 'Minimum capacity to be available before scheduling more mirrors preemptively. Premium and ' \
                'Ultimate only.'
            optional :mirror_max_capacity,
              desc: 'Maximum number of mirrors that can be synchronizing at the same time. Premium and Ultimate only.'
            optional :mirror_max_delay,
              desc: 'Maximum time (in minutes) between updates that a mirror can have when scheduled to ' \
                'synchronize. Premium and Ultimate only.'
            optional :package_metadata_purl_types,
              desc: 'List of [package registry metadata to sync](https://docs.gitlab.com/administration/settings/security_and_compliance/#choose-package-registry-metadata-to-sync). See [the list](https://gitlab.com/gitlab-org/gitlab/-/blob/ace16c20d5da7c4928dd03fb139692638b557fe3/app/models/concerns/enums/package_metadata.rb#L5) of the available values. GitLab Self-Managed, Ultimate only.'
            optional :password_lowercase_required,
              desc: 'If `true`, passwords require at least one lowercase letter. Premium and Ultimate only.'
            optional :password_number_required,
              desc: 'If `true`, passwords require at least one number. Premium and Ultimate only.'
            optional :password_symbol_required,
              desc: 'If `true`, passwords require at least one symbol character. Premium and Ultimate only.'
            optional :password_uppercase_required,
              desc: 'If `true`, passwords require at least one uppercase letter. Premium and Ultimate only.'
            optional :project_secrets_limit,
              desc: 'Maximum number of secrets allowed per project in Secrets Manager. Default: 100. To disable the ' \
                'limit, set to `0`. Ultimate only. ' \
                '[Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/219436) in GitLab 18.9.'
            optional :scan_execution_policies_action_limit,
              desc: 'Maximum number of `actions` per scan execution policy. Defaults to `0` and cannot be set above `20`.'
            optional :scan_execution_policies_schedule_limit,
              desc: 'Maximum number of `type: schedule` rules per scan execution policy. Defaults to `0` and cannot be set above `20`.'
            optional :secret_push_protection_available,
              desc: 'If `true`, allows projects to enable secret push protection. This does not enable secret push protection. Ultimate only.'
            optional :security_approval_policies_limit,
              desc: 'Maximum number of active merge request approval policies per security policy project. Defaults to `5` and cannot be set above `20`.'
            optional :security_mr_report_cache_lifetime_minutes,
              desc: 'Number of minutes to cache security reports on merge requests (10-60). Default: 10. Premium and ' \
                'Ultimate only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/223399) in GitLab ' \
                '18.10.'
            optional :shared_runners_minutes,
              desc: 'Set the maximum number of compute minutes that a group can use on instance runners per month. ' \
                'Premium and Ultimate only.'
            optional :unconfirmed_users_delete_after_days,
              desc: 'Specifies how many days after account creation to delete users who have not confirmed their ' \
                'email. Only applicable if `delete_unconfirmed_users` is set to `true`. Must be `1` or greater. ' \
                'Default is `7`. GitLab Self-Managed, Premium and Ultimate only.'
            # rubocop:enable API/ParameterType
          end
        end

        class_methods do
          extend ::Gitlab::Utils::Override

          override :optional_attributes
          def optional_attributes
            super + EE::ApplicationSettingsHelper.possible_licensed_attributes
          end
        end
      end
    end
  end
end
