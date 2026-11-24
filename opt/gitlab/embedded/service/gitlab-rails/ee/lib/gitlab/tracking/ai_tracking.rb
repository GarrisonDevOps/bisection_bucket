# frozen_string_literal: true

module Gitlab
  module Tracking
    # Class for tracking AI usage events.
    # @see doc/development/ai_features/usage_tracking.md for documentation
    module AiTracking
      extend AiUsageEventsRegistryDsl

      register_feature(:code_suggestions) do
        deprecated_events(code_suggestions_requested: 1) # old data

        events(
          code_suggestion_shown_in_ide: 2,
          code_suggestion_accepted_in_ide: 3,
          code_suggestion_rejected_in_ide: 4
        ) do |context|
          context.slice(*%w[unique_tracking_id suggestion_size language branch_name
            ide_name ide_vendor ide_version
            extension_name extension_version language_server_version
            model_name model_engine])
        end

        deprecated_events(code_suggestion_direct_access_token_refresh: 5) # old data
      end

      register_feature(:chat) do
        events(request_duo_chat_response: 6)

        events(
          tool_succeeded_duo_chat: 48,
          tool_failed_duo_chat: 49
        ) do |context|
          {
            session_id: Integer(context['session_id'], exception: false),
            tool_name: context['tool_name'],
            flow_type: context['flow_type'],
            trigger_source: context['trigger_source'],
            model: context['model']
          }.compact
        end
        # IDs 50-53 are reserved by in-flight merge requests.

        events(report_duo_chat_token_usage: 54) do |context|
          { request_id: context['request_id'], usage: context['usage'] }.compact
        end

        events(complete_duo_chat_response: 55) do |context|
          { request_id: context['request_id'], error_code: context['error_code'] }.compact
        end
      end

      register_feature(:troubleshoot_job) do
        events(troubleshoot_job: 7) do |context|
          {
            job_id: context['job'].id,
            project_id: context['job'].project_id,
            pipeline_id: context['job'].pipeline&.id,
            merge_request_id: context['job'].pipeline&.merge_request_id
          }
        end
      end

      register_feature(:agent_platform) do
        events(
          agent_platform_session_created: 8,
          agent_platform_session_started: 9,
          agent_platform_session_finished: 19,
          agent_platform_session_dropped: 20,
          agent_platform_session_stopped: 21,
          agent_platform_session_resumed: 22,
          report_agent_platform_token_usage: 59,
          agent_platform_session_input_required: 61) do |context|
          {
            project_id: context['project']&.id,
            session_id: context['value'],
            flow_type: context['label'],
            environment: context['property']
          }.merge(context['verification_run'].to_s == 'true' ? { verification_run: 'true' } : {})
        end

        transformation(:report_agent_platform_token_usage) do |context|
          { usage: context['usage'] }.compact
        end

        non_user_action_events(:report_agent_platform_token_usage)

        events(
          view_duo_agentic_subscription_expired_empty_state: 28,
          click_duo_agentic_subscription_expired_upgrade: 29,
          click_duo_agentic_subscription_expired_learn_more: 30
        )
      end

      register_feature(:code_review) do
        events(
          encounter_duo_code_review_error_during_review: 10,
          find_no_issues_duo_code_review_after_review: 11,
          find_nothing_to_review_duo_code_review_on_mr: 12,
          post_comment_duo_code_review_on_diff: 13,
          react_thumbs_up_on_duo_code_review_comment: 14,
          react_thumbs_down_on_duo_code_review_comment: 15,
          request_review_duo_code_review_on_mr_by_author: 16,
          request_review_duo_code_review_on_mr_by_non_author: 17,
          excluded_files_from_duo_code_review: 18,
          publish_duo_code_review_comments: 32
        )

        events(
          create_duo_suggested_reviewers: 56,
          assign_duo_suggested_reviewer: 57
        ) do |context|
          {
            merge_request_id: Integer(context['property'], exception: false),
            count: context['value']
          }
        end

        events(approve_merge_request_duo_code_review: 58) do |context|
          { merge_request_id: context['property'] }
        end
      end

      register_feature(:mcp) do
        events(
          start_mcp_tool_call: 23,
          finish_mcp_tool_call: 24
        ) do |context|
          {
            request_id: context['request_id'],
            tool_name: context['tool_name'],
            has_tool_call_success: context['has_tool_call_success'],
            failure_reason: context['failure_reason'],
            error_status: context['error_status'],
            dispatched_tool_name: context['dispatched_tool_name']
          }
        end
      end
      register_feature(:fix_pipeline) do
        events(
          fix_pipeline_suggestion_posted: 25,
          fix_pipeline_suggestion_applied: 26
        )
      end

      register_feature(:duo_workflow) do
        events(duo_workflow_workload_completed: 27) do |context|
          context.slice(*%w[workflow_id workflow_definition])
        end
      end
      register_feature(:ai_catalog) do
        events(restore_ai_catalog_item: 31)
      end

      register_feature(:summarize_review) do
        events(summarize_review: 36)
      end

      register_feature(:summarize_new_merge_request) do
        events(summarize_new_merge_request: 33)
      end

      register_feature(:generate_merge_commit_message) do
        events(generate_merge_commit_message: 37)
      end

      register_feature(:duo_messaging) do
        events(ai_duo_messaging_feedback_submitted: 38) do |context|
          {
            feedback: context['label'],
            workflow_id: context['value'],
            surface: context['property']
          }
        end

        # receive_slack_duo_mention and block_slack_duo_mention are not
        # registered here: they can fire without a user (unlinked Slack
        # accounts), while ai_usage_events requires one.
        events(trigger_slack_duo: 47) do |context|
          { project_id: context['project']&.id }
        end
      end

      register_feature(:request_duo_vulnerability_resolution) do
        events(request_duo_vulnerability_resolution: 34)
      end

      register_feature(:explain_vulnerability) do
        events(explain_vulnerability: 35)
      end

      register_feature(:fix_code) do
        events(fix_code: 39)
      end

      register_feature(:refactor_code) do
        events(refactor_code: 40)
      end

      register_feature(:write_tests) do
        events(write_tests: 41)
      end

      register_feature(:explain_code) do
        events(explain_code: 42)
      end
      # IDs 43-44 are reserved by in-flight merge requests.

      register_feature(:feature_discovery) do
        events(resolve_feature_discovery_search: 46) do |context|
          {
            resolution_tier: context['label'],
            latency_ms: context['value']
          }
        end
      end
      # Current highest event ID: 61, next available: 62

      class << self
        def track_event(event_name, **context_hash)
          return unless AiTracking.registered_events.key?(event_name.to_s)

          event = build_event_model(event_name, context_hash)

          store_to_postgres(event)
          store_to_clickhouse(event)

          track_user_activity(context_hash[:user])
        end

        def track_user_activity(user)
          ::Ai::UserMetrics.refresh_last_activity_on(user)
        end

        private

        def base_attributes
          %w[user timestamp event namespace_id].freeze
        end

        def build_event_model(event_name, context_hash = {})
          context_hash = context_hash.with_indifferent_access

          attributes = apply_transformations(event_name, context_hash)

          basic_attributes = context_hash.slice(*base_attributes).merge(attributes.slice(*base_attributes))
          extra_attributes = attributes.except(*base_attributes).merge(client_attributes)

          ::Ai::UsageEvent.new(basic_attributes.merge(event: event_name, extras: extra_attributes))
        end

        # Absent keys mean no request lineage, which the dashboards read as system.
        def client_attributes
          identity = ::Gitlab::Tracking::ClientIdentity.current
          return {} unless identity

          { client_type: identity.type, client_name: identity.name, client_version: identity.version }.compact
        end

        def store_to_clickhouse(event)
          return unless ::Gitlab::ClickHouse.globally_enabled_for_analytics?

          event.store_to_clickhouse
        end

        def store_to_postgres(event)
          return unless event.store_to_pg

          ::Ai::TokenDailyUsage.buffer_usage(event)
        end

        def apply_transformations(event_name, context_hash)
          result = {}.with_indifferent_access

          AiTracking.registered_transformations(event_name).each do |transformation|
            transformation_result = transformation.call(context_hash.merge(result))

            result.merge!(transformation_result)
          end.compact

          unless result[:namespace_id]
            guessed_namespace_id = guess_namespace_id(context_hash.merge(result))

            result[:namespace_id] = guessed_namespace_id if guessed_namespace_id
          end

          result
        end

        def guess_namespace_id(context_hash)
          related_namespace(context_hash)&.id
        end

        def related_namespace(context_hash)
          # Order matters. project should take precedence over namespace
          project = if context_hash[:project]
                      context_hash[:project]
                    elsif context_hash[:project_id]
                      ::Project.find_by_id(context_hash[:project_id])
                    end

          return project.project_namespace if project

          if context_hash[:namespace]
            context_hash[:namespace]
          elsif context_hash[:namespace_id]
            ::Namespace.find_by_id(context_hash[:namespace_id])
          end
        end
      end
    end
  end
end
