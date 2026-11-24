# frozen_string_literal: true

module Integrations
  module SlackInteractions
    module SlackBlockActions
      class DuoApprovalDecisionHandler < BaseHandler
        include Gitlab::InternalEventsTracking

        DECISION_EVENT = 'ai_duo_messaging_tool_approval_resolved'
        SURFACE = 'slack'
        VALUE_FORMAT = /\A(?<workflow_id>\d+):(?<fingerprint>\h+)\z/

        def execute
          return unless parsed_value && workflow
          return unless Feature.enabled?(:slack_duo_api_flow, workflow.resource_parent&.root_ancestor)
          return notify_clicker(account_not_linked_text) unless current_user

          result = ::Ai::DuoWorkflows::ResolveToolApprovalService.new(
            workflow: workflow,
            current_user: current_user,
            approved: approved?,
            fingerprint: parsed_value[:fingerprint],
            surface: SURFACE
          ).execute

          return notify_clicker(failure_text(result.reason)) if result.error?

          track_decision
          render_outcome
        end

        private

        def approved?
          action[:action_id] == ::Ai::Messaging::Adapters::Slack::ToolApprovalCard::APPROVE_ACTION_ID
        end

        def failure_text(reason)
          case reason
          when :not_owner, :not_authorized
            s_('DuoSlack|Only the person who started this session can respond to this request.')
          when :stale_request, :not_approvable
            s_('DuoSlack|This approval request has already been answered.')
          else
            s_('DuoSlack|This request can no longer be answered.')
          end
        end

        def account_not_linked_text
          s_('DuoSlack|Your Slack account is not connected to a GitLab account, so you cannot respond to this request.')
        end

        # The service stored the decision, so the adapter renders the card from session state.
        def render_outcome
          return unless slack_installation

          ::Ai::Messaging::Adapters::Slack.from_callback_context(callback_context)
            .on_approval_resolved(callback_context: callback_context, workflow: workflow)
        rescue StandardError => e
          Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)
        end

        def notify_clicker(text)
          return if callback_context['channel_id'].blank?
          return unless slack_installation

          slack_api.post_ephemeral(
            channel: callback_context['channel_id'],
            user: user_id,
            text: text,
            thread_ts: callback_context['thread_ts']
          )
        rescue StandardError => e
          Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)
        end

        def callback_context
          workflow.messaging_callback_context || {}
        end

        def track_decision
          track_internal_event(
            DECISION_EVENT,
            user: current_user,
            namespace: workflow.resource_parent&.root_ancestor,
            additional_properties: {
              label: approved? ? 'approved' : 'denied',
              value: workflow.id,
              property: SURFACE
            }
          )
        end

        def parsed_value
          VALUE_FORMAT.match(action[:value].to_s)
        end
        strong_memoize_attr :parsed_value

        def workflow
          ::Ai::DuoWorkflows::Workflow.find_by_id(parsed_value[:workflow_id])
        end
        strong_memoize_attr :workflow

        def current_user
          ChatNames::FindUserService.new(team_id, user_id).execute&.user
        end
        strong_memoize_attr :current_user
      end
    end
  end
end
