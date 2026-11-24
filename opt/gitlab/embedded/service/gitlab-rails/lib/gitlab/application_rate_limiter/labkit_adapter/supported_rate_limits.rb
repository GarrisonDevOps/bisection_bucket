# frozen_string_literal: true

module Gitlab
  module ApplicationRateLimiter
    module LabkitAdapter
      # Single source of truth for the keys this adapter handles, paired
      # with ee/lib/ee/gitlab/application_rate_limiter/labkit_adapter/
      # supported_rate_limits.rb (EE additions, prepended via prepend_mod).
      #
      # Per-rule conventions:
      #   characteristics: ordered slots of the labkit Redis key. Callers
      #                    pass `scope:` as a hash keyed by these names,
      #                    e.g. { project: project, user: current_user }.
      #                    Polymorphic rules list every accepted slot;
      #                    labkit's '_unknown_' sentinel fills slots not in
      #                    scope, keeping Redis keys disjoint per real type.
      #   limit:           static threshold (Integer) or a zero-arity callable
      #                    resolved per check against application settings.
      #                    Omitted for entries whose threshold arrives per call
      #                    (see threshold_from_caller and cost_mode below).
      #   period:          window as an Integer (seconds), an ActiveSupport
      #                    duration, or a callable. Omitted for cost_mode entries
      #                    (the interval arrives per call).
      #   action:          forwarded to the labkit Rule; the adapter
      #                    returns labkit's boolean decision to the caller.
      #                    Use staged_rule instead of Rule.new to ship a new
      #                    key in log mode behind an enforce feature flag.
      #
      # `web_hook_calls{,_low,_mid}` receive their threshold per call from
      # PlanLimits and so omit `limit:` (it resolves to 0, matching the legacy
      # hash, which carried no threshold for them); the adapter forwards the
      # caller's value via rule_context rather than treating it as an override.
      module SupportedRateLimits
        ENFORCED_FACT = :rate_limit_enforced

        StagedRule = Struct.new(:rule, :log_rule, :enforce, keyword_init: true)

        def self.all
          @all ||= limiters.freeze
        end

        def self.rules
          @rules ||= definitions.transform_values { |d| d.is_a?(StagedRule) ? d.rule : d }.freeze
        end

        def self.staged_rules
          @staged_rules ||= definitions.select { |_, d| d.is_a?(StagedRule) }.freeze
        end

        # Test hook: the registry is captured at first build, so specs that add a
        # key must clear every memo.
        def self.reset!
          @all = @definitions = @rules = @staged_rules = nil
        end

        def self.definitions
          @definitions ||= rule_definitions
        end
        private_class_method :definitions

        def self.staged?(key)
          staged_rules.key?(key)
        end

        def self.enforced?(key, scope)
          staged_rules.fetch(key).enforce.call(scope)
        end

        # Lets a new key move from logging to blocking with a feature flag rather
        # than a code change.
        def self.staged_rule(enforce:, match: {}, **attrs)
          raise ArgumentError, 'staged_rule sets action itself' if attrs.key?(:action)
          raise ArgumentError, 'enforce must take the scope' unless enforce.arity == 1

          StagedRule.new(
            rule: ::Labkit::RateLimit::Rule.new(
              **attrs, match: match.merge(ENFORCED_FACT => true), action: :limit
            ),
            log_rule: ::Labkit::RateLimit::Rule.new(
              **attrs, name: "#{attrs.fetch(:name)}_log", match: match.merge(ENFORCED_FACT => false), action: :log
            ),
            enforce: enforce
          )
        end

        def self.limiter_for(key)
          all.fetch(key)
        end

        def self.limiter_name(key)
          "applimiter_#{key}"
        end

        def self.rule_for(key)
          rules.fetch(key)
        end

        def self.limit_for(key, context: nil)
          resolve_value(rule_for(key).limit, context)
        end

        def self.period_for(key, context: nil)
          resolve_value(rule_for(key).period, context)
        end

        def self.cost_mode?(key)
          cost_mode_keys.include?(key)
        end

        # Mirrors labkit's own Evaluator#resolve_value contract (see
        # gitlab-labkit's lib/labkit/rate_limit/evaluator.rb) so that the
        # values we resolve here match what labkit will actually enforce.
        # Variadic callables (negative arity, e.g. ->(*ctx) { ... }) are
        # intentionally excluded, not by oversight: labkit only forwards
        # rule_context to callables with exactly one required parameter
        # (->(ctx) { ... }); passing it to a splat would wrap it in an
        # array (args == [rule_context]) instead of binding it directly,
        # which is a worse footgun. Keep this check in lockstep with
        # labkit's arity >= 1 condition rather than "fixing" it to accept
        # variadic callables.
        def self.accepts_context?(value)
          value.respond_to?(:call) && value.respond_to?(:arity) && value.arity >= 1
        end

        def self.rule_definitions # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity -- static registry of rate-limit definitions
          {
            ai_action: ::Labkit::RateLimit::Rule.new(
              name: 'limit_ai_actions_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.ai_action_api_rate_limit },
              period: 8.hours,
              action: :limit
            ),
            auto_rollback_deployment: ::Labkit::RateLimit::Rule.new(
              name: 'limit_auto_rollbacks_by_environment',
              characteristics: %i[environment],
              limit: 1,
              period: 3.minutes,
              action: :limit
            ),
            autocomplete_users: ::Labkit::RateLimit::Rule.new(
              name: 'limit_user_autocompletes_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.autocomplete_users_limit },
              period: 1.minute,
              action: :limit
            ),
            autocomplete_users_unauthenticated: ::Labkit::RateLimit::Rule.new(
              name: 'limit_user_autocompletes_by_ip',
              characteristics: %i[ip],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.autocomplete_users_unauthenticated_limit
              },
              period: 1.minute,
              action: :limit
            ),
            bitbucket_server_import: ::Labkit::RateLimit::Rule.new(
              name: 'limit_bitbucket_server_imports_by_user',
              characteristics: %i[user],
              limit: 6,
              period: 1.minute,
              action: :limit
            ),
            bulk_delete_todos: ::Labkit::RateLimit::Rule.new(
              name: 'limit_bulk_todo_deletes_by_user',
              characteristics: %i[user],
              limit: 6,
              period: 1.minute,
              action: :limit
            ),
            bulk_import: ::Labkit::RateLimit::Rule.new(
              name: 'limit_bulk_imports_by_user',
              characteristics: %i[user],
              limit: 6,
              period: 1.minute,
              action: :limit
            ),
            ci_config_cache_entries_per_user: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:ci_config_cache_entry_limit, scope[:user]) },
              name: 'limit_ci_config_cache_entries_by_user',
              characteristics: %i[user],
              limit: 30,
              period: 1.minute
            ),
            ci_job_processed_subscription: ::Labkit::RateLimit::Rule.new(
              name: 'limit_ci_job_processed_events_by_project',
              characteristics: %i[project],
              # Counted per event: 50 job transitions, each triggering 2 topics.
              limit: 100,
              period: 1.minute,
              action: :limit
            ),
            ci_lint: ::Labkit::RateLimit::Rule.new(
              name: 'limit_ci_lint_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.ci_lint_limit_per_user },
              period: 1.minute,
              action: :limit
            ),
            ci_pipeline_statuses_subscription: ::Labkit::RateLimit::Rule.new(
              name: 'limit_ci_pipeline_status_events_by_project',
              characteristics: %i[project],
              # Counted per event: 50 pipeline transitions, each triggering 4 topics.
              limit: 200,
              period: 1.minute,
              action: :limit
            ),
            code_suggestions_api_endpoint: ::Labkit::RateLimit::Rule.new(
              name: 'limit_code_suggestions_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.code_suggestions_api_rate_limit },
              period: 1.minute,
              action: :limit
            ),
            collaborative_editing_update: ::Labkit::RateLimit::Rule.new(
              name: 'limit_collaborative_editing_updates_by_user_document',
              characteristics: %i[user document_key],
              limit: 600,
              period: 1.minute,
              action: :limit
            ),
            context_commits_write: ::Labkit::RateLimit::Rule.new(
              name: 'limit_context_commit_writes_by_user',
              characteristics: %i[user],
              limit: 10,
              period: 1.minute,
              action: :limit
            ),
            collaborative_editing_update_by_user: ::Labkit::RateLimit::Rule.new(
              name: 'limit_collaborative_editing_updates_by_user',
              characteristics: %i[user],
              limit: 1200,
              period: 1.minute,
              action: :limit
            ),
            collaborative_editing_bytes_by_user: ::Labkit::RateLimit::Rule.new(
              name: 'limit_collaborative_editing_bytes_by_user',
              characteristics: %i[user],
              limit: 64.megabytes,
              period: 1.minute,
              action: :limit
            ),
            contributor_graphs_unauthenticated: staged_rule(
              enforce: ->(scope) {
                ::Feature.enabled?(:contributor_graphs_unauthenticated_rate_limit, scope[:project])
              },
              name: 'limit_unauthenticated_contributor_graphs_by_project',
              characteristics: %i[project],
              limit: 30,
              period: 1.minute
            ),
            create_organization_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_organization_creates_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.create_organization_api_limit },
              period: 1.minute,
              action: :limit
            ),
            cross_reference_checks: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:enforce_cross_reference_limits, scope[:user]) },
              name: 'limit_cross_reference_checks_by_user',
              characteristics: %i[user namespace],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.cross_reference_checks_limit },
              period: 1.minute
            ),
            delete_all_todos: ::Labkit::RateLimit::Rule.new(
              name: 'limit_todo_bulk_deletes_by_user',
              characteristics: %i[user],
              limit: 1,
              period: 5.minutes,
              action: :limit
            ),
            delete_merged_branches: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:delete_merged_branches_rate_limit, scope[:user]) },
              name: 'limit_delete_merged_branches_by_user',
              characteristics: %i[user],
              limit: 60,
              period: 1.minute
            ),
            deployment_delete: ::Labkit::RateLimit::Rule.new(
              name: 'limit_deployment_deletes_by_user',
              characteristics: %i[user],
              limit: 500,
              period: 1.minute,
              action: :limit
            ),
            discussions_resolve: ::Labkit::RateLimit::Rule.new(
              name: 'limit_discussion_resolves_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.discussions_resolve_limit },
              period: 1.minute,
              action: :limit
            ),
            draft_notes_create: ::Labkit::RateLimit::Rule.new(
              name: 'limit_draft_note_creates_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.draft_notes_create_limit },
              period: 1.minute,
              action: :limit
            ),
            downstream_pipeline_trigger: ::Labkit::RateLimit::Rule.new(
              name: 'limit_downstream_pipeline_triggers_by_project_user_sha',
              characteristics: %i[project user sha],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.downstream_pipeline_trigger_limit_per_project_user_sha
              },
              period: 1.minute,
              action: :limit
            ),
            email_verification: ::Labkit::RateLimit::Rule.new(
              name: 'limit_email_verifies_by_subject',
              characteristics: %i[subject],
              limit: 10,
              period: 10.minutes,
              action: :limit
            ),
            email_verification_code_send: ::Labkit::RateLimit::Rule.new(
              name: 'limit_email_verification_sends_by_user',
              characteristics: %i[user],
              limit: 10,
              period: 1.hour,
              action: :limit
            ),
            environment_delete_rows: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:rate_limit_environment_delete_rows, scope[:user]) },
              name: 'limit_environment_delete_rows_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.environment_delete_rows_limit_per_user },
              period: 1.minute
            ),
            error_tracking_sentry_cache_entries_per_project: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:error_tracking_sentry_cache_entry_limit, scope[:project]) },
              name: 'limit_error_tracking_sentry_cache_entries_by_project',
              characteristics: %i[project],
              limit: 300,
              period: 1.minute
            ),
            error_tracking_sentry_cache_entries_per_user: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:error_tracking_sentry_cache_entry_limit, scope[:project]) },
              name: 'limit_error_tracking_sentry_cache_entries_by_user_project',
              characteristics: %i[user project],
              limit: 60,
              period: 1.minute
            ),
            feature_flag_user_list_write_bytes: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:rate_limit_feature_flag_user_list_write_bytes, scope[:user]) },
              name: 'limit_feature_flag_user_list_write_bytes_by_user',
              characteristics: %i[user],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.feature_flag_user_list_write_bytes_limit_per_user
              },
              period: 1.minute
            ),
            feature_library_search: ::Labkit::RateLimit::Rule.new(
              name: 'limit_feature_library_searches_by_user',
              characteristics: %i[user],
              limit: 60,
              period: 1.minute,
              action: :limit
            ),
            feature_library_catalog: ::Labkit::RateLimit::Rule.new(
              name: 'limit_feature_library_catalog_requests_by_user',
              characteristics: %i[user],
              limit: 10,
              period: 1.minute,
              action: :limit
            ),
            fetch_google_ip_list: ::Labkit::RateLimit::Rule.new(
              name: 'limit_google_ip_list_fetches_by_scope',
              characteristics: %i[scope],
              limit: 10,
              period: 1.minute,
              action: :limit
            ),
            fogbugz_import: ::Labkit::RateLimit::Rule.new(
              name: 'limit_fogbugz_imports_by_user',
              characteristics: %i[user],
              limit: 1,
              period: 1.minute,
              action: :limit
            ),
            geo_proxy: ::Labkit::RateLimit::Rule.new(
              name: 'limit_geo_proxy_requests_by_ip',
              characteristics: %i[ip],
              limit: 60,
              period: 1.minute,
              action: :limit
            ),
            git_push_per_project: ::Labkit::RateLimit::Rule.new(
              name: 'limit_git_pushes_by_project',
              characteristics: %i[project],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.git_push_per_project_limit },
              period: 1.minute,
              action: :limit
            ),
            gitea_import: ::Labkit::RateLimit::Rule.new(
              name: 'limit_gitea_imports_by_user',
              characteristics: %i[user],
              limit: 6,
              period: 1.minute,
              action: :limit
            ),
            github_gists_import: ::Labkit::RateLimit::Rule.new(
              name: 'limit_github_gists_imports_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.github_gists_import_limit },
              period: 1.minute,
              action: :limit
            ),
            gitlab_shell_operation: ::Labkit::RateLimit::Rule.new(
              name: 'limit_gitlab_shell_operations_by_action_project_actor',
              # `:repo_path`, not `:project`: lib/api/internal/base.rb passes
              # params[:project] as a repo-path String (see
              # lib/api/helpers/internal_helpers.rb:173), not a Project AR.
              # Naming the slot `:project` reserved it for AR routing, which
              # left only two primitive slots for three String values
              # (action, path, ip) on the untrusted-IP branch and silently
              # dropped the IP, collapsing every untrusted-IP client to a
              # given repo into one Redis counter.
              characteristics: %i[action repo_path user key ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.gitlab_shell_operation_limit },
              period: 1.minute,
              action: :limit
            ),
            gitlab_shell_operation_per_actor: ::Labkit::RateLimit::Rule.new(
              name: 'limit_gitlab_shell_operations_by_actor',
              characteristics: %i[user deploy_key deploy_token],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.gitlab_shell_operation_per_actor_limit },
              period: 1.minute,
              action: :limit
            ),
            glql: ::Labkit::RateLimit::Rule.new(
              name: 'limit_glql_queries_by_query_sha',
              characteristics: %i[query_sha],
              limit: 1,
              period: 15.minutes,
              action: :limit
            ),
            # Cost-mode: each GLQL request is charged its database seconds, across all databases.
            glql_db_seconds_by_query_sha: ::Labkit::RateLimit::Rule.new(
              name: 'limit_glql_db_seconds_by_query_sha',
              characteristics: %i[query_sha],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.glql_db_seconds_per_query_limit },
              period: 15.minutes,
              action: :limit
            ),
            glql_db_seconds_by_user: ::Labkit::RateLimit::Rule.new(
              name: 'limit_glql_db_seconds_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.glql_db_seconds_per_user_limit },
              period: 15.minutes,
              action: :limit
            ),
            glql_db_seconds_by_ip: ::Labkit::RateLimit::Rule.new(
              name: 'limit_glql_db_seconds_by_ip',
              characteristics: %i[ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.glql_db_seconds_per_ip_limit },
              period: 15.minutes,
              action: :limit
            ),
            glql_duo_db_seconds_by_user: ::Labkit::RateLimit::Rule.new(
              name: 'limit_glql_duo_db_seconds_by_user',
              characteristics: %i[user],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.glql_duo_db_seconds_per_user_limit
              },
              period: 15.minutes,
              action: :limit
            ),
            group_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_group_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.group_api_limit },
              period: 1.minute,
              action: :limit
            ),
            group_archive_unarchive_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_group_archive_unarchive_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.group_archive_unarchive_api_limit },
              period: 1.minute,
              action: :limit
            ),
            group_delete_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_group_deletes_api_by_user',
              characteristics: %i[user],
              limit: 60,
              period: 1.minute,
              action: :limit
            ),
            group_download_export: ::Labkit::RateLimit::Rule.new(
              name: 'limit_group_export_downloads_by_user_group',
              characteristics: %i[user group],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.group_download_export_limit },
              period: 1.minute,
              action: :limit
            ),
            group_export: ::Labkit::RateLimit::Rule.new(
              name: 'limit_group_exports_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.group_export_limit },
              period: 1.minute,
              action: :limit
            ),
            group_hooks_create: ::Labkit::RateLimit::Rule.new(
              name: 'limit_group_hooks_creates_by_group_user',
              characteristics: %i[group user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.group_hooks_create_limit },
              period: 1.minute,
              action: :limit
            ),
            group_import: ::Labkit::RateLimit::Rule.new(
              name: 'limit_group_imports_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.group_import_limit },
              period: 1.minute,
              action: :limit
            ),
            group_invited_groups_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_group_invited_groups_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.group_invited_groups_api_limit },
              period: 1.minute,
              action: :limit
            ),
            group_permanent_delete_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_group_permanent_deletes_api_by_user',
              characteristics: %i[user],
              limit: 10,
              period: 1.minute,
              action: :limit
            ),
            group_projects_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_group_projects_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.group_projects_api_limit },
              period: 1.minute,
              action: :limit
            ),
            group_relations_export: ::Labkit::RateLimit::Rule.new(
              name: 'limit_group_relations_exports_by_user_group',
              characteristics: %i[user group],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.group_relations_export_limit },
              period: 1.minute,
              action: :limit
            ),
            group_relations_export_download: ::Labkit::RateLimit::Rule.new(
              name: 'limit_group_relations_export_downloads_by_user_group',
              characteristics: %i[user group],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.group_relations_export_download_limit },
              period: 1.minute,
              action: :limit
            ),
            group_shared_groups_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_group_shared_groups_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.group_shared_groups_api_limit },
              period: 1.minute,
              action: :limit
            ),
            groups_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_groups_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.groups_api_limit },
              period: 1.minute,
              action: :limit
            ),
            groups_create: ::Labkit::RateLimit::Rule.new(
              name: 'limit_groups_created_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.group_create_limit },
              period: 1.day,
              action: :limit
            ),
            iam_silent_login_reject: ::Labkit::RateLimit::Rule.new(
              name: 'limit_iam_silent_login_rejects_by_ip',
              characteristics: %i[ip],
              limit: 60,
              period: 1.minute,
              action: :limit
            ),
            import_source_user_notification: ::Labkit::RateLimit::Rule.new(
              name: 'limit_import_source_user_notifications_by_source_user',
              characteristics: %i[import_source_user],
              limit: 1,
              period: 8.hours,
              action: :limit
            ),
            issuable_csv_export: ::Labkit::RateLimit::Rule.new(
              name: 'limit_issuable_csv_exports_by_user',
              characteristics: %i[user],
              limit: 20,
              period: 1.hour,
              action: :limit
            ),
            issuable_csv_import: ::Labkit::RateLimit::Rule.new(
              name: 'limit_issuable_csv_imports_by_user',
              characteristics: %i[user],
              limit: -> {
                next 0 unless ::Feature.enabled?(:issuable_csv_import_rate_limit, :instance)

                Gitlab::CurrentSettings.current_application_settings.issuable_csv_import_limit
              },
              period: 1.hour,
              action: :limit
            ),
            issues_create: ::Labkit::RateLimit::Rule.new(
              name: 'limit_issues_by_project_user_external_author',
              characteristics: %i[project user external_author],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.issues_create_limit },
              period: 1.minute,
              action: :limit
            ),
            work_item_move: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:work_item_move_rate_limit_enforce, scope[:user]) },
              name: 'limit_work_item_moves_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.work_item_move_limit },
              period: 1.minute
            ),
            jobs_index: ::Labkit::RateLimit::Rule.new(
              name: 'limit_jobs_index_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.project_jobs_api_rate_limit },
              period: 1.minute,
              action: :limit
            ),
            label_delete: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:label_delete_rate_limit, scope[:user]) },
              name: 'limit_label_deletes_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.label_delete_limit },
              period: 1.minute
            ),
            large_blob_download: ::Labkit::RateLimit::Rule.new(
              name: 'limit_large_blob_downloads_by_project',
              characteristics: %i[project],
              limit: 5,
              period: 1.minute,
              action: :limit
            ),
            markdown_upload_bytes: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:markdown_uploads_rate_limit_enforce, scope[:user]) },
              name: 'limit_markdown_upload_bytes_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.markdown_upload_limit_megabytes_per_day.megabytes
              },
              period: 1.day
            ),
            members_delete: ::Labkit::RateLimit::Rule.new(
              name: 'limit_member_deletes_by_source_user',
              characteristics: %i[project group user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.members_delete_limit },
              period: 1.minute,
              action: :limit
            ),
            # Anonymous callers have no user to gate the flag on, so they follow the instance-wide state.
            merge_request_diffs_page: staged_rule(
              enforce: ->(scope) {
                ::Feature.enabled?(:merge_request_diffs_page_rate_limit, scope[:user] || :instance)
              },
              name: 'limit_mr_diffs_page_loads_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.merge_request_diffs_page_request_limit },
              period: 1.minute
            ),
            # Anonymous callers have no user to gate the flag on, so they follow the instance-wide state.
            merge_request_diff_resources: staged_rule(
              enforce: ->(scope) {
                ::Feature.enabled?(:merge_request_diff_resources_rate_limit, scope[:user] || :instance)
              },
              name: 'limit_mr_diff_resources_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.merge_request_diff_resources_request_limit
              },
              period: 1.minute
            ),
            merge_requests_create: ::Labkit::RateLimit::Rule.new(
              name: 'limit_merge_requests_created_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.merge_requests_create_limit },
              period: 1.minute,
              action: :limit
            ),
            merge_requests_rebase: ::Labkit::RateLimit::Rule.new(
              name: 'limit_merge_request_rebases_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.merge_requests_rebase_limit },
              period: 1.minute,
              action: :limit
            ),
            metric_definitions_download: staged_rule(
              enforce: ->(_scope) { ::Feature.enabled?(:rate_limit_metric_definitions, :instance) },
              name: 'limit_metric_definition_downloads_by_ip',
              characteristics: %i[ip],
              limit: 30,
              period: 1.minute
            ),
            milestone_destroy: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:milestone_destroy_rate_limit, scope[:user]) },
              name: 'limit_milestone_destroys_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.milestone_destroy_limit },
              period: 1.minute
            ),
            mobile_push_notifications: ::Labkit::RateLimit::Rule.new(
              name: 'limit_mobile_push_notifications_by_user',
              characteristics: %i[user],
              limit: 60,
              period: 1.hour,
              action: :limit
            ),
            namespace_exists: ::Labkit::RateLimit::Rule.new(
              name: 'limit_namespace_existence_checks_by_user',
              characteristics: %i[user],
              limit: 20,
              period: 1.minute,
              action: :limit
            ),
            namespace_work_item_changes_broadcast: ::Labkit::RateLimit::Rule.new(
              name: 'limit_namespace_work_item_change_broadcasts_by_namespace',
              characteristics: %i[namespace],
              limit: 5,
              period: 15.seconds,
              action: :limit
            ),
            notes_create: ::Labkit::RateLimit::Rule.new(
              name: 'limit_notes_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.notes_create_limit },
              period: 1.minute,
              action: :limit
            ),
            notes_create_by_external_author: ::Labkit::RateLimit::Rule.new(
              name: 'limit_notes_by_project_external_author',
              characteristics: %i[project external_author],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.notes_create_limit },
              period: 1.minute,
              action: :limit
            ),
            notes_update: ::Labkit::RateLimit::Rule.new(
              name: 'limit_note_edits_by_user',
              characteristics: %i[user],
              limit: 300,
              period: 1.minute,
              action: :limit
            ),
            notification_emails: ::Labkit::RateLimit::Rule.new(
              name: 'limit_notification_emails_by_parent_user',
              characteristics: %i[project group user],
              limit: 1000,
              period: 1.day,
              action: :limit
            ),
            oauth_dynamic_registration: ::Labkit::RateLimit::Rule.new(
              name: 'limit_oauth_registrations_by_ip',
              characteristics: %i[ip],
              limit: 10,
              period: 1.hour,
              action: :limit
            ),
            observability_bff_session: ::Labkit::RateLimit::Rule.new(
              name: 'limit_observability_bff_sessions_by_user',
              characteristics: %i[user],
              limit: 20,
              period: 1.minute,
              action: :limit
            ),
            offline_export: ::Labkit::RateLimit::Rule.new(
              name: 'limit_offline_exports_by_user',
              characteristics: %i[user],
              limit: 6,
              period: 1.minute,
              action: :limit
            ),
            offline_import: ::Labkit::RateLimit::Rule.new(
              name: 'limit_offline_imports_by_user',
              characteristics: %i[user],
              limit: 6,
              period: 1.minute,
              action: :limit
            ),
            offset_pagination_count_cache_write: ::Labkit::RateLimit::Rule.new(
              name: 'limit_offset_pagination_count_cache_writes_by_scope',
              characteristics: %i[scope],
              limit: 10_000,
              period: Gitlab::Pagination::OffsetPagination::COUNT_CACHE_EXPIRES_IN,
              action: :limit
            ),
            organization_user_create: ::Labkit::RateLimit::Rule.new(
              name: 'limit_organization_user_creates_by_user',
              characteristics: %i[user],
              limit: 20,
              period: 1.minute,
              action: :limit
            ),
            package_final_store_path_authorize: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:package_final_store_path_authorize_rate_limit, scope[:user]) },
              name: 'limit_package_final_store_path_authorizes_by_actor',
              characteristics: %i[user deploy_token],
              limit: ->(ctx) { ctx&.dig(:threshold) || 1_500 },
              period: 1.minute
            ),
            pages_domain_create: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:pages_domain_rate_limits, scope[:user]) },
              name: 'limit_pages_domain_creates_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.pages_domain_create_limit },
              period: 1.day
            ),
            pages_domain_verify: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:pages_domain_rate_limits, scope[:user]) },
              name: 'limit_pages_domain_verifies_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.pages_domain_verify_limit },
              period: 1.minute
            ),
            organization_user_delete: ::Labkit::RateLimit::Rule.new(
              name: 'limit_organization_user_deletes_by_user',
              characteristics: %i[user],
              limit: 20,
              period: 1.minute,
              action: :limit
            ),
            organization_user_list: ::Labkit::RateLimit::Rule.new(
              name: 'limit_organization_user_lists_by_user',
              characteristics: %i[user],
              limit: 120,
              period: 1.minute,
              action: :limit
            ),
            organization_user_update: ::Labkit::RateLimit::Rule.new(
              name: 'limit_organization_user_updates_by_user',
              characteristics: %i[user],
              limit: 20,
              period: 1.minute,
              action: :limit
            ),
            permanent_email_failure: ::Labkit::RateLimit::Rule.new(
              name: 'limit_permanent_email_failures_by_email',
              characteristics: %i[email],
              limit: 5,
              period: 1.day,
              action: :limit
            ),
            phone_verification_send_code: ::Labkit::RateLimit::Rule.new(
              name: 'limit_phone_verification_sends_by_user',
              characteristics: %i[user],
              limit: 5,
              period: 1.day,
              action: :limit
            ),
            phone_verification_verify_code: ::Labkit::RateLimit::Rule.new(
              name: 'limit_phone_verification_verifies_by_user',
              characteristics: %i[user],
              limit: 5,
              period: 1.day,
              action: :limit
            ),
            pipeline_cancel: ::Labkit::RateLimit::Rule.new(
              name: 'limit_pipeline_cancels_by_user_pipeline',
              characteristics: %i[user ci_pipeline],
              limit: 5,
              period: 1.minute,
              action: :limit
            ),
            pipeline_delete: ::Labkit::RateLimit::Rule.new(
              name: 'limit_pipeline_deletes_by_user_pipeline',
              characteristics: %i[user ci_pipeline],
              limit: 5,
              period: 1.minute,
              action: :limit
            ),
            pipeline_cancel_per_project: ::Labkit::RateLimit::Rule.new(
              name: 'limit_pipeline_cancels_by_user_project',
              characteristics: %i[user project],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.pipeline_cancel_limit_per_user_project
              },
              period: 1.minute,
              action: :limit
            ),
            pipeline_retry: ::Labkit::RateLimit::Rule.new(
              name: 'limit_pipeline_retries_by_user_pipeline',
              characteristics: %i[user ci_pipeline],
              limit: 5,
              period: 1.minute,
              action: :limit
            ),
            # Busiest observed actor plus headroom, measured in
            # https://gitlab.com/gitlab-org/gitlab/-/issues/627233.
            pipeline_retry_per_project: ::Labkit::RateLimit::Rule.new(
              name: 'limit_pipeline_retries_by_user_project',
              characteristics: %i[user project],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.pipeline_retry_limit_per_user_project
              },
              period: 1.minute,
              action: :limit
            ),
            job_retry: ::Labkit::RateLimit::Rule.new(
              name: 'limit_job_retries_by_user_job',
              characteristics: %i[user ci_build],
              limit: 3,
              period: 1.minute,
              action: :limit
            ),
            job_retry_per_project: ::Labkit::RateLimit::Rule.new(
              name: 'limit_job_retries_by_user_project',
              characteristics: %i[user project],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.job_retry_limit_per_user_project
              },
              period: 1.minute,
              action: :limit
            ),
            job_play: ::Labkit::RateLimit::Rule.new(
              name: 'limit_job_plays_by_user_job',
              characteristics: %i[user ci_build],
              limit: 3,
              period: 1.minute,
              action: :limit
            ),
            job_play_per_project: ::Labkit::RateLimit::Rule.new(
              name: 'limit_job_plays_by_user_project',
              characteristics: %i[user project],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.job_play_limit_per_user_project
              },
              period: 1.minute,
              action: :limit
            ),
            # Every sampled actor but one stayed under this; see
            # https://gitlab.com/gitlab-org/gitlab/-/issues/627268.
            pipeline_delete_per_project: ::Labkit::RateLimit::Rule.new(
              name: 'limit_pipeline_deletes_by_user_project',
              characteristics: %i[user project],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.pipeline_delete_limit_per_user_project
              },
              period: 1.minute,
              action: :limit
            ),
            job_erase: ::Labkit::RateLimit::Rule.new(
              name: 'limit_job_erases_by_user_job',
              characteristics: %i[user ci_build],
              limit: 5,
              period: 1.minute,
              action: :limit
            ),
            job_erase_per_project: ::Labkit::RateLimit::Rule.new(
              name: 'limit_job_erases_by_user_project',
              characteristics: %i[user project],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.job_erase_limit_per_user_project
              },
              period: 1.minute,
              action: :limit
            ),
            job_cancel: ::Labkit::RateLimit::Rule.new(
              name: 'limit_job_cancels_by_user_job',
              characteristics: %i[user ci_build],
              limit: 5,
              period: 1.minute,
              action: :limit
            ),
            job_cancel_per_project: ::Labkit::RateLimit::Rule.new(
              name: 'limit_job_cancels_by_user_project',
              characteristics: %i[user project],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.job_cancel_limit_per_user_project
              },
              period: 1.minute,
              action: :limit
            ),
            pages_deployments_api: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:pages_deployments_api_rate_limit, scope[:user]) },
              name: 'limit_pages_deployments_api_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.pages_deployments_api_limit },
              period: 1.minute
            ),
            pages_deployments_api_unauthenticated: staged_rule(
              enforce: ->(_scope) { ::Feature.enabled?(:pages_deployments_api_rate_limit, :instance) },
              name: 'limit_pages_deployments_api_by_ip',
              characteristics: %i[ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.pages_deployments_api_limit },
              period: 1.minute
            ),
            pipelines_create: ::Labkit::RateLimit::Rule.new(
              name: 'limit_pipelines_by_project_user_sha',
              characteristics: %i[project user sha],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.pipeline_limit_per_project_user_sha },
              period: 1.minute,
              action: :limit
            ),
            pipelines_created_per_user: ::Labkit::RateLimit::Rule.new(
              name: 'limit_pipelines_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.pipeline_limit_per_user },
              period: 1.minute,
              action: :limit
            ),
            placeholder_reassignment: ::Labkit::RateLimit::Rule.new(
              name: 'limit_placeholder_reassignments_by_user',
              characteristics: %i[user],
              limit: 5,
              period: 1.minute,
              action: :limit
            ),
            play_pipeline_schedule: ::Labkit::RateLimit::Rule.new(
              name: 'limit_pipeline_schedule_plays_by_user_schedule',
              characteristics: %i[user ci_pipeline_schedule],
              limit: 1,
              period: 1.minute,
              action: :limit
            ),
            pipeline_schedule_management: ::Labkit::RateLimit::Rule.new(
              name: 'limit_pipeline_schedule_management_actions_by_user',
              characteristics: %i[user],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.pipeline_schedule_management_limit_per_user
              },
              period: 1.minute,
              action: :limit
            ),
            pipeline_trigger_management: ::Labkit::RateLimit::Rule.new(
              name: 'limit_pipeline_trigger_management_actions_by_user',
              characteristics: %i[user],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.pipeline_trigger_management_limit_per_user
              },
              period: 1.minute,
              action: :limit
            ),
            profile_add_new_email: ::Labkit::RateLimit::Rule.new(
              name: 'limit_profile_email_adds_by_user',
              characteristics: %i[user],
              limit: 5,
              period: 1.minute,
              action: :limit
            ),
            profile_resend_email_confirmation: ::Labkit::RateLimit::Rule.new(
              name: 'limit_profile_email_confirm_resends_by_user',
              characteristics: %i[user],
              limit: 5,
              period: 1.minute,
              action: :limit
            ),
            profile_update_username: ::Labkit::RateLimit::Rule.new(
              name: 'limit_profile_username_updates_by_user',
              characteristics: %i[user],
              limit: 10,
              period: 1.minute,
              action: :limit
            ),
            project_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.project_api_limit },
              period: 1.minute,
              action: :limit
            ),
            project_delete_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_deletes_api_by_user',
              characteristics: %i[user],
              limit: 60,
              period: 1.minute,
              action: :limit
            ),
            project_download_export: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_export_downloads_by_user_project',
              characteristics: %i[user project],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.project_download_export_limit },
              period: 1.minute,
              action: :limit
            ),
            project_export: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_exports_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.project_export_limit },
              period: 1.minute,
              action: :limit
            ),
            project_fork_sync: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_fork_syncs_by_project_user',
              characteristics: %i[project user],
              limit: 10,
              period: 30.minutes,
              action: :limit
            ),
            project_generate_new_export: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_export_generations_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.project_export_limit },
              period: 1.minute,
              action: :limit
            ),
            project_hooks_create: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_hooks_creates_by_project_user',
              characteristics: %i[project user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.project_hooks_create_limit },
              period: 1.minute,
              action: :limit
            ),
            project_import: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_imports_by_user_action',
              characteristics: %i[user action],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.project_import_limit },
              period: 1.minute,
              action: :limit
            ),
            project_invited_groups_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_invited_groups_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.project_invited_groups_api_limit },
              period: 1.minute,
              action: :limit
            ),
            project_members_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_members_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.project_members_api_limit },
              period: 1.minute,
              action: :limit
            ),
            project_permanent_delete_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_permanent_deletes_api_by_user',
              characteristics: %i[user],
              limit: 10,
              period: 1.minute,
              action: :limit
            ),
            project_relations_export: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_relations_exports_by_user_project',
              characteristics: %i[user project],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.project_relations_export_limit },
              period: 1.minute,
              action: :limit
            ),
            project_relations_export_download: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_relations_export_downloads_by_user_project',
              characteristics: %i[user project],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.project_relations_export_download_limit
              },
              period: 1.minute,
              action: :limit
            ),
            project_repositories_archive: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_repository_archives_by_project_user',
              characteristics: %i[project user],
              limit: ->(ctx) { ctx&.dig(:threshold) || 5 },
              period: 1.minute,
              action: :limit
            ),
            repositories_archive: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:cross_project_archive_rate_limit, scope[:user]) },
              name: 'limit_repository_archives_by_user',
              characteristics: %i[user],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.project_repositories_archive_limit
              },
              period: 1.minute
            ),
            repositories_archive_unauthenticated: staged_rule(
              enforce: ->(_scope) { ::Feature.enabled?(:cross_project_archive_rate_limit, :instance) },
              name: 'limit_repository_archives_by_ip',
              characteristics: %i[ip],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings
                  .project_repositories_archive_unauthenticated_limit
              },
              period: 1.minute
            ),
            project_repositories_blame: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_repository_blame_by_user_project',
              characteristics: %i[user project],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.project_repositories_blame_limit },
              period: 1.minute,
              action: :limit
            ),
            project_repositories_blame_unauthenticated: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_repository_blame_by_ip',
              characteristics: %i[ip],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings
                  .project_repositories_blame_unauthenticated_limit
              },
              period: 1.minute,
              action: :limit
            ),
            project_repositories_blobs_batch: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_repository_blobs_batch_by_project_user',
              characteristics: %i[project user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.project_repositories_blobs_batch_limit },
              period: 1.minute,
              action: :limit
            ),
            project_repositories_changelog: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_repository_changelogs_by_user_project',
              characteristics: %i[user project],
              limit: 5,
              period: 1.minute,
              action: :limit
            ),
            project_repositories_changed_paths: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_repository_changed_paths_by_user_project',
              characteristics: %i[user project],
              limit: 30,
              period: 1.minute,
              action: :limit
            ),
            project_repositories_diff_stats: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_repository_diff_stats_by_user_project',
              characteristics: %i[user project],
              limit: 30,
              period: 1.minute,
              action: :limit
            ),
            project_repositories_diverging_commits: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_repository_diverging_commits_by_user_project',
              characteristics: %i[user project],
              limit: 30,
              period: 1.minute,
              action: :limit
            ),
            project_repositories_health: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_repository_health_by_project',
              characteristics: %i[project],
              limit: 5,
              period: 1.hour,
              action: :limit
            ),
            project_repository_commits_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_project_repository_commits_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.project_repository_commits_api_limit
              },
              period: 1.minute,
              action: :limit
            ),
            project_testing_integration: ::Labkit::RateLimit::Rule.new(
              name: 'limit_integration_tests_by_project_user',
              characteristics: %i[project user],
              limit: 5,
              period: 1.minute,
              action: :limit
            ),
            project_value_stream_analytics: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:project_value_stream_analytics_rate_limit, scope[:project]) },
              name: 'limit_project_value_stream_analytics_by_project_user_or_ip',
              characteristics: %i[project user ip],
              limit: 60,
              period: 1.minute
            ),
            projects_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_projects_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.projects_api_limit },
              period: 10.minutes,
              action: :limit
            ),
            projects_api_rate_limit_unauthenticated: ::Labkit::RateLimit::Rule.new(
              name: 'limit_projects_api_by_ip',
              characteristics: %i[ip],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.projects_api_rate_limit_unauthenticated
              },
              period: 10.minutes,
              action: :limit
            ),
            projects_create: ::Labkit::RateLimit::Rule.new(
              name: 'limit_projects_created_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.project_create_limit },
              period: 1.day,
              action: :limit
            ),
            protected_branch_write: staged_rule(
              enforce: ->(scope) {
                ::Feature.enabled?(:protected_branch_write_rate_limit_enforce, scope[:namespace])
              },
              name: 'limit_protected_branch_writes_by_user_namespace',
              characteristics: %i[user namespace],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.protected_branch_write_limit
              },
              period: 1.hour
            ),
            raw_blob: ::Labkit::RateLimit::Rule.new(
              name: 'limit_raw_blobs_by_project_path',
              characteristics: %i[project path],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.raw_blob_request_limit },
              period: 1.minute,
              action: :limit
            ),
            raw_blob_unauthenticated: ::Labkit::RateLimit::Rule.new(
              name: 'limit_raw_blobs_by_project',
              characteristics: %i[project],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.raw_blob_request_limit_unauthenticated },
              period: 1.minute,
              action: :limit
            ),
            release_evidence_collections_per_user: staged_rule(
              enforce: ->(scope) {
                ::Feature.enabled?(:rate_limit_release_evidence_collections_per_user, scope[:user])
              },
              name: 'limit_release_evidence_collections_by_user',
              characteristics: %i[user],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.release_evidence_collections_limit_per_user
              },
              period: 1.minute
            ),
            release_writes_per_project: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:rate_limit_release_writes_per_project, scope[:project]) },
              name: 'limit_release_writes_by_project',
              characteristics: %i[project],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.release_writes_limit_per_project },
              period: 1.minute
            ),
            release_writes_per_user: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:rate_limit_release_writes_per_user, scope[:user]) },
              name: 'limit_release_writes_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.release_writes_limit_per_user },
              period: 1.minute
            ),
            runner_jobs_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_runner_jobs_by_job_token',
              characteristics: %i[job_token_sha],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.runner_jobs_endpoints_api_limit },
              period: 1.minute,
              action: :limit
            ),
            runner_job_list_completed_statuses: staged_rule(
              enforce: ->(scope) {
                ::Feature.enabled?(:ci_enforce_runner_job_list_completed_statuses_limit, scope[:user])
              },
              name: 'limit_runner_job_list_completed_status_filters_by_user',
              characteristics: %i[user],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.runner_job_list_completed_statuses_limit_per_user
              },
              period: 1.minute
            ),
            runner_job_list_project_filtered: staged_rule(
              enforce: ->(scope) {
                ::Feature.enabled?(:ci_rate_limit_rest_runner_job_list_project_filtered, scope[:user])
              },
              name: 'limit_runner_job_list_project_filters_by_user',
              characteristics: %i[user],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.runner_job_list_project_filtered_limit_per_user
              },
              period: 1.minute
            ),
            runner_jobs_patch_trace_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_runner_job_traces_by_job_token',
              characteristics: %i[job_token_sha],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.runner_jobs_patch_trace_api_limit },
              period: 1.minute,
              action: :limit
            ),
            runner_jobs_request_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_runner_job_requests_by_runner_token',
              characteristics: %i[runner_token_sha],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.runner_jobs_request_api_limit },
              period: 1.minute,
              action: :limit
            ),
            runner_manager_creation: ::Labkit::RateLimit::Rule.new(
              name: 'limit_runner_manager_creations_by_runner',
              characteristics: %i[ci_runner],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.runner_manager_creation_limit },
              period: 10.minutes,
              action: :limit
            ),
            runner_manager_list: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:ci_rate_limit_rest_runner_manager_list, scope[:user]) },
              name: 'limit_runner_managers_listed_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.runner_manager_list_limit_per_user },
              period: 1.minute
            ),
            search_index_blob_repair: ::Labkit::RateLimit::Rule.new(
              name: 'limit_search_index_blob_repairs_by_project',
              characteristics: %i[project],
              limit: 1,
              period: 30.minutes,
              action: :limit
            ),
            search_index_integrity: ::Labkit::RateLimit::Rule.new(
              name: 'limit_search_index_integrity_checks_by_project_or_group',
              characteristics: %i[project group],
              limit: 1,
              period: 30.minutes,
              action: :limit
            ),
            search_rate_limit: ::Labkit::RateLimit::Rule.new(
              name: 'limit_searches_by_user_scope',
              characteristics: %i[user search_scope],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.search_rate_limit },
              period: 1.minute,
              action: :limit
            ),
            search_rate_limit_unauthenticated: ::Labkit::RateLimit::Rule.new(
              name: 'limit_searches_by_ip',
              characteristics: %i[ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.search_rate_limit_unauthenticated },
              period: 1.minute,
              action: :limit
            ),
            service_account_creation: ::Labkit::RateLimit::Rule.new(
              name: 'limit_service_account_creates_by_user',
              characteristics: %i[user],
              limit: 10,
              period: 1.minute,
              action: :limit
            ),
            # service_desk_outbound_emails_per_{hour,day} carry no static
            # threshold: the limit is looked up per namespace from PlanLimits
            # and passed in via the caller's `threshold:` argument, same
            # pattern as web_hook_calls above.
            service_desk_outbound_emails_per_hour: ::Labkit::RateLimit::Rule.new(
              name: 'limit_service_desk_outbound_emails_per_hour_by_namespace',
              characteristics: %i[namespace],
              limit: ->(ctx) { ctx&.dig(:threshold) || 0 },
              period: 1.hour,
              action: :limit
            ),
            service_desk_outbound_emails_per_day: ::Labkit::RateLimit::Rule.new(
              name: 'limit_service_desk_outbound_emails_per_day_by_namespace',
              characteristics: %i[namespace],
              limit: ->(ctx) { ctx&.dig(:threshold) || 0 },
              period: 1.day,
              action: :limit
            ),
            # Email on Push reuses the service_desk_outbound_emails_per_*
            # threshold value but counts into its own buckets, so exhausting the
            # push quota never throttles Service Desk sends, and vice versa.
            #
            emails_on_push_outbound_emails_per_hour: ::Labkit::RateLimit::Rule.new(
              name: 'limit_emails_on_push_outbound_emails_per_hour_by_namespace',
              characteristics: %i[namespace],
              limit: ->(ctx) { ctx&.dig(:threshold) || 0 },
              period: 1.hour,
              action: :limit
            ),
            emails_on_push_outbound_emails_per_day: ::Labkit::RateLimit::Rule.new(
              name: 'limit_emails_on_push_outbound_emails_per_day_by_namespace',
              characteristics: %i[namespace],
              limit: ->(ctx) { ctx&.dig(:threshold) || 0 },
              period: 1.day,
              action: :limit
            ),
            # Pipelines Email reuses the service_desk_outbound_emails_per_*
            # threshold value but counts into its own buckets, so exhausting the
            # pipeline quota never throttles Service Desk or Email on Push sends,
            # and vice versa.
            #
            pipelines_email_outbound_emails_per_hour: ::Labkit::RateLimit::Rule.new(
              name: 'limit_pipelines_email_outbound_emails_per_hour_by_namespace',
              characteristics: %i[namespace],
              limit: ->(ctx) { ctx&.dig(:threshold) || 0 },
              period: 1.hour,
              action: :limit
            ),
            pipelines_email_outbound_emails_per_day: ::Labkit::RateLimit::Rule.new(
              name: 'limit_pipelines_email_outbound_emails_per_day_by_namespace',
              characteristics: %i[namespace],
              limit: ->(ctx) { ctx&.dig(:threshold) || 0 },
              period: 1.day,
              action: :limit
            ),
            # Dedups the suppression note posted when Service Desk email is
            # rate limited: at most one per work item per hour, regardless of
            # how many suppressed sends happen in that window.
            service_desk_suppression_notice: ::Labkit::RateLimit::Rule.new(
              name: 'limit_service_desk_suppression_notices_by_work_item',
              characteristics: %i[work_item],
              limit: 1,
              period: 1.hour,
              action: :limit
            ),
            slack_app_commands: ::Labkit::RateLimit::Rule.new(
              name: 'limit_slack_app_commands_by_slack_workspace',
              characteristics: %i[slack_workspace],
              limit: 60,
              period: 1.minute,
              action: :limit
            ),
            slack_app_events: ::Labkit::RateLimit::Rule.new(
              name: 'limit_slack_app_events_by_slack_workspace',
              characteristics: %i[slack_workspace],
              limit: 60,
              period: 1.minute,
              action: :limit
            ),
            slack_app_interactions: ::Labkit::RateLimit::Rule.new(
              name: 'limit_slack_app_interactions_by_slack_workspace',
              characteristics: %i[slack_workspace],
              limit: 300,
              period: 1.minute,
              action: :limit
            ),
            snippets_create: ::Labkit::RateLimit::Rule.new(
              name: 'limit_snippets_created_by_user',
              characteristics: %i[user],
              limit: 300,
              period: 1.hour,
              action: :limit
            ),
            spam_check: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:spam_check_rate_limit, scope[:user]) },
              name: 'limit_spam_checks_by_user',
              characteristics: %i[user],
              limit: 60,
              period: 1.minute
            ),
            ssh_certificate_authentication: ::Labkit::RateLimit::Rule.new(
              name: 'limit_ssh_certificate_authentication_by_ip',
              characteristics: %i[ip],
              limit: 300,
              period: 1.minute,
              action: :limit
            ),
            system_hooks_create: ::Labkit::RateLimit::Rule.new(
              name: 'limit_system_hooks_creates_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.system_hooks_create_limit },
              period: 1.minute,
              action: :limit
            ),
            tags_create: ::Labkit::RateLimit::Rule.new(
              name: 'limit_tag_creates_by_project',
              characteristics: %i[project],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.tags_create_limit },
              period: 30.minutes,
              action: :limit
            ),
            temporary_email_failure: ::Labkit::RateLimit::Rule.new(
              name: 'limit_temporary_email_failures_by_email',
              characteristics: %i[email],
              limit: 300,
              period: 1.day,
              action: :limit
            ),
            test_report_show: ::Labkit::RateLimit::Rule.new(
              name: 'limit_test_report_shows_by_user',
              characteristics: %i[user],
              limit: 60,
              period: 1.minute,
              action: :limit
            ),
            test_report_show_unauthenticated: ::Labkit::RateLimit::Rule.new(
              name: 'limit_test_report_shows_by_ip',
              characteristics: %i[ip],
              limit: 60,
              period: 1.minute,
              action: :limit
            ),
            todos_list_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_todos_list_api_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.todos_list_api_limit },
              period: 1.minute,
              action: :limit
            ),
            token_exchange: ::Labkit::RateLimit::Rule.new(
              name: 'limit_token_exchanges_by_user',
              characteristics: %i[user],
              limit: 60,
              period: 1.minute,
              action: :limit
            ),
            track_internal_events: ::Labkit::RateLimit::Rule.new(
              name: 'limit_internal_event_tracking_by_user',
              characteristics: %i[user],
              limit: 200,
              period: 1.minute,
              action: :limit
            ),
            update_environment_canary_ingress: ::Labkit::RateLimit::Rule.new(
              name: 'limit_canary_ingress_updates_by_environment',
              characteristics: %i[environment],
              limit: 1,
              period: 1.minute,
              action: :limit
            ),
            update_namespace_name: ::Labkit::RateLimit::Rule.new(
              name: 'limit_namespace_name_updates_by_namespace',
              characteristics: %i[namespace],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.update_namespace_name_rate_limit },
              period: 1.hour,
              action: :limit
            ),
            user_contributed_projects_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_user_contributed_projects_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.user_contributed_projects_api_limit },
              period: 1.minute,
              action: :limit
            ),
            user_followers: ::Labkit::RateLimit::Rule.new(
              name: 'limit_user_followers_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.users_api_limit_followers },
              period: 1.minute,
              action: :limit
            ),
            user_following: ::Labkit::RateLimit::Rule.new(
              name: 'limit_user_following_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.users_api_limit_following },
              period: 1.minute,
              action: :limit
            ),
            user_gpg_key: ::Labkit::RateLimit::Rule.new(
              name: 'limit_user_gpg_key_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.users_api_limit_gpg_key },
              period: 1.minute,
              action: :limit
            ),
            user_gpg_keys: ::Labkit::RateLimit::Rule.new(
              name: 'limit_user_gpg_keys_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.users_api_limit_gpg_keys },
              period: 1.minute,
              action: :limit
            ),
            user_large_commit_request: ::Labkit::RateLimit::Rule.new(
              name: 'limit_large_commit_requests_by_user',
              characteristics: %i[user],
              limit: 3,
              period: 30.seconds,
              action: :limit
            ),
            user_projects_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_user_projects_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.user_projects_api_limit },
              period: 1.minute,
              action: :limit
            ),
            user_sign_in: ::Labkit::RateLimit::Rule.new(
              name: 'limit_signins_by_user',
              characteristics: %i[user],
              limit: 5,
              period: 10.minutes,
              action: :limit
            ),
            user_sign_up: ::Labkit::RateLimit::Rule.new(
              name: 'limit_signups_by_ip',
              characteristics: %i[ip],
              limit: 20,
              period: 1.minute,
              action: :limit
            ),
            user_ssh_key: ::Labkit::RateLimit::Rule.new(
              name: 'limit_user_ssh_key_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.users_api_limit_ssh_key },
              period: 1.minute,
              action: :limit
            ),
            user_ssh_keys: ::Labkit::RateLimit::Rule.new(
              name: 'limit_user_ssh_keys_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.users_api_limit_ssh_keys },
              period: 1.minute,
              action: :limit
            ),
            user_starred_projects_api: ::Labkit::RateLimit::Rule.new(
              name: 'limit_user_starred_projects_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.user_starred_projects_api_limit },
              period: 1.minute,
              action: :limit
            ),
            user_status: ::Labkit::RateLimit::Rule.new(
              name: 'limit_user_status_api_by_user_or_ip',
              characteristics: %i[user ip],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.users_api_limit_status },
              period: 1.minute,
              action: :limit
            ),
            username_exists: ::Labkit::RateLimit::Rule.new(
              name: 'limit_username_existence_checks_by_ip',
              characteristics: %i[ip],
              limit: 20,
              period: 1.minute,
              action: :limit
            ),
            users_get_by_id: ::Labkit::RateLimit::Rule.new(
              name: 'limit_user_lookups_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.users_get_by_id_limit },
              period: 10.minutes,
              action: :limit
            ),
            value_stream_stage_metrics: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:vsa_stage_metrics_rate_limit, scope[:user]) },
              name: 'limit_value_stream_stage_metrics_by_user_or_ip',
              characteristics: %i[user ip],
              limit: 150,
              period: 1.minute
            ),
            # web_hook_calls{,_low,_mid} carry no static threshold: the limit
            # is looked up per namespace from PlanLimits and passed in via the
            # caller's `threshold:` argument. They therefore omit `limit:` (it
            # resolves to 0, exactly as the legacy hash did, which carried no
            # threshold for them). `threshold_from_caller: true` opts the entry
            # out of the adapter's threshold-override bail so the caller's value
            # is forwarded through to labkit's one-arity limit callable via
            # rule_context. The `1.minute` period is the registry value and is
            # not caller-controlled.
            web_hook_calls: ::Labkit::RateLimit::Rule.new(
              name: 'limit_web_hook_calls_by_namespace',
              characteristics: %i[namespace],
              limit: ->(ctx) { ctx&.dig(:threshold) || 0 },
              period: 1.minute,
              action: :limit
            ),
            web_hook_calls_low: ::Labkit::RateLimit::Rule.new(
              name: 'limit_web_hook_calls_low_by_namespace',
              characteristics: %i[namespace],
              limit: ->(ctx) { ctx&.dig(:threshold) || 0 },
              period: 1.minute,
              action: :limit
            ),
            web_hook_calls_mid: ::Labkit::RateLimit::Rule.new(
              name: 'limit_web_hook_calls_mid_by_namespace',
              characteristics: %i[namespace],
              limit: ->(ctx) { ctx&.dig(:threshold) || 0 },
              period: 1.minute,
              action: :limit
            ),
            # integration_executions{,_datadog} follow the web_hook_calls pattern:
            # the threshold comes from PlanLimits via the caller's `threshold:`.
            # Datadog has its own counter so it cannot exhaust the shared budget.
            integration_executions: ::Labkit::RateLimit::Rule.new(
              name: 'limit_integration_executions_by_namespace',
              characteristics: %i[namespace],
              limit: ->(ctx) { ctx&.dig(:threshold) || 0 },
              period: 1.minute,
              action: :limit
            ),
            integration_executions_datadog: ::Labkit::RateLimit::Rule.new(
              name: 'limit_integration_executions_datadog_by_namespace',
              characteristics: %i[namespace],
              limit: ->(ctx) { ctx&.dig(:threshold) || 0 },
              period: 1.minute,
              action: :limit
            ),
            # Same as web_hook_calls, but counted per organization for system
            # hooks managed by organization admins, which have no namespace.
            organization_web_hook_calls: ::Labkit::RateLimit::Rule.new(
              name: 'limit_web_hook_calls_by_organization',
              characteristics: %i[organization],
              limit: ->(ctx) { ctx&.dig(:threshold) || 0 },
              period: 1.minute,
              action: :limit
            ),
            web_hook_event_resend: ::Labkit::RateLimit::Rule.new(
              name: 'limit_web_hook_event_resends_by_parent_user',
              characteristics: %i[project group user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.web_hook_event_resend_limit },
              period: 1.minute,
              action: :limit
            ),
            web_hook_test: ::Labkit::RateLimit::Rule.new(
              name: 'limit_web_hook_tests_by_parent_user',
              characteristics: %i[project group organization user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.web_hook_test_limit },
              period: 1.minute,
              action: :limit
            ),
            wiki_read_unauthenticated: staged_rule(
              enforce: ->(scope) {
                ::Feature.enabled?(:wiki_read_unauthenticated_rate_limit_enforce, scope[:project] || scope[:group])
              },
              name: 'limit_unauthenticated_wiki_reads_by_parent',
              characteristics: %i[project group],
              limit: -> {
                Gitlab::CurrentSettings.current_application_settings.wiki_read_request_limit_unauthenticated
              },
              period: 1.minute
            ),
            work_item_bulk_update: ::Labkit::RateLimit::Rule.new(
              name: 'limit_work_item_bulk_updates_by_user',
              characteristics: %i[user],
              limit: 30,
              period: 1.minute,
              action: :limit
            ),
            work_item_delete: ::Labkit::RateLimit::Rule.new(
              name: 'limit_work_item_deletes_by_user',
              characteristics: %i[user],
              limit: 300,
              period: 1.minute,
              action: :limit
            ),
            work_item_hierarchy_add_children: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:work_item_hierarchy_add_children_limits, scope[:user]) },
              name: 'limit_work_item_hierarchy_add_children_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.work_item_hierarchy_add_children_limit },
              period: 1.minute
            ),
            work_item_hierarchy_reorder: ::Labkit::RateLimit::Rule.new(
              name: 'limit_work_item_hierarchy_reorders_by_user',
              characteristics: %i[user],
              limit: 120,
              period: 1.minute,
              action: :limit
            ),
            work_item_saved_view_broadcast: ::Labkit::RateLimit::Rule.new(
              name: 'limit_work_item_saved_view_broadcasts_by_saved_view',
              characteristics: %i[saved_view],
              limit: 30,
              period: 1.minute,
              action: :limit
            ),
            work_item_update: staged_rule(
              enforce: ->(scope) { ::Feature.enabled?(:work_item_update_rate_limit, scope[:user]) },
              name: 'limit_work_item_updates_by_user',
              characteristics: %i[user],
              limit: -> { Gitlab::CurrentSettings.current_application_settings.work_item_update_limit },
              period: 1.minute
            ),
            # Per-database Sidekiq resource-usage (DB duration) limits,
            # one Limiter per database. Cost-mode (the per-job DB duration is the
            # `check(cost:)` value, not a call count). threshold and interval are
            # both caller-supplied: SidekiqLimits.limits_for resolves the worker's
            # urgency rule and any ApplicationSetting override upstream, so the
            # labkit Rule must use that resolved value (not a static constant).
            # They therefore carry no static limit/period; both arrive per call
            # via rule_context and these keys are absent from rate_limits.
            main_db_duration_limit_per_worker: ::Labkit::RateLimit::Rule.new(
              name: 'limit_main_db_duration_per_worker',
              characteristics: %i[worker_name],
              limit: ->(ctx) { ctx&.dig(:threshold) || 0 },
              period: ->(ctx) { ctx&.dig(:interval) || 0 },
              action: :limit
            ),
            ci_db_duration_limit_per_worker: ::Labkit::RateLimit::Rule.new(
              name: 'limit_ci_db_duration_per_worker',
              characteristics: %i[worker_name],
              limit: ->(ctx) { ctx&.dig(:threshold) || 0 },
              period: ->(ctx) { ctx&.dig(:interval) || 0 },
              action: :limit
            ),
            sec_db_duration_limit_per_worker: ::Labkit::RateLimit::Rule.new(
              name: 'limit_sec_db_duration_per_worker',
              characteristics: %i[worker_name],
              limit: ->(ctx) { ctx&.dig(:threshold) || 0 },
              period: ->(ctx) { ctx&.dig(:interval) || 0 },
              action: :limit
            )
          }
        end

        def self.limiters
          rules.keys.index_with { |key| build_limiter(key) }
        end

        def self.build_limiter(key)
          ::Labkit::RateLimit::Limiter.new(
            name: limiter_name(key),
            rules: [bypass_rule_for(key), rule_for(key), staged_rules[key]&.log_rule].compact,
            redis: ::Gitlab::Redis::RateLimiting,
            logger: ::Gitlab::AppLogger
          )
        end
        private_class_method :build_limiter

        # A synthetic :skip rule ahead of the real throttle rule: bypass-header
        # traffic (identifier[:bypass_header] == '1') terminates here before
        # touching Redis, so it stays visible via rule_evaluations_total{action="skip"}
        # without back-filling the real rule's rate. Named per key so each
        # limit's bypass volume is distinguishable in Prometheus/Grafana.
        def self.bypass_rule_for(key)
          ::Labkit::RateLimit::Rule.new(
            name: "#{key}_bypass",
            match: { bypass_header: ::Gitlab::Throttle::BYPASS_HEADER_VALUE },
            characteristics: [],
            limit: 0, # unused: action: :skip terminates evaluation before limit/period are consulted
            period: 60, # unused: action: :skip terminates evaluation before limit/period are consulted
            action: :skip
          )
        end
        private_class_method :bypass_rule_for

        def self.cost_mode_keys
          Set.new([:main_db_duration_limit_per_worker, :ci_db_duration_limit_per_worker,
            :sec_db_duration_limit_per_worker, :glql_db_seconds_by_query_sha,
            :glql_db_seconds_by_user, :glql_db_seconds_by_ip, :glql_duo_db_seconds_by_user]).freeze
        end
        private_class_method :cost_mode_keys

        def self.resolve_value(value, context)
          return value.to_i unless value.respond_to?(:call)

          value = accepts_context?(value) ? value.call(context) : value.call
          value.to_i
        end
        private_class_method :resolve_value
      end
    end
  end
end

Gitlab::ApplicationRateLimiter::LabkitAdapter::SupportedRateLimits.prepend_mod
