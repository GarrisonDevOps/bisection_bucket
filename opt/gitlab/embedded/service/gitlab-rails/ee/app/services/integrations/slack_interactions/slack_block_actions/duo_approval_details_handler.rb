# frozen_string_literal: true

module Integrations
  module SlackInteractions
    module SlackBlockActions
      class DuoApprovalDetailsHandler < BaseHandler
        VALUE_FORMAT = /\A(?<workflow_id>\d+):(?<fingerprint>\h+)\z/

        def execute
          return unless parsed_value && workflow
          return unless Feature.enabled?(:slack_duo_api_flow, workflow.resource_parent&.root_ancestor)

          open_view(view)
        end

        private

        def view
          return DuoToolRequestModal.account_not_linked_view unless current_user
          return DuoToolRequestModal.not_owner_view unless workflow.invoked_by?(current_user)
          return DuoToolRequestModal.stale_view unless pending&.fingerprint == parsed_value[:fingerprint]

          DuoToolRequestModal.new(pending, session_url: workflow.messaging_callback_context&.dig('session_url')).build
        end

        def open_view(view)
          trigger_id = params[:trigger_id]
          return if trigger_id.blank?
          return unless slack_installation

          slack_api.open_view(trigger_id: trigger_id, view: view)
        end

        def pending
          return unless workflow.tool_call_approval_required?

          ::Ai::DuoWorkflows::PendingToolApproval.for(workflow)
        end
        strong_memoize_attr :pending

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
