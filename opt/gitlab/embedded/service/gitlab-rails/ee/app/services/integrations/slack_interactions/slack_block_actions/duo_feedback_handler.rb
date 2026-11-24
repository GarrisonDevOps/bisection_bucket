# frozen_string_literal: true

module Integrations
  module SlackInteractions
    module SlackBlockActions
      class DuoFeedbackHandler < BaseHandler
        include Gitlab::InternalEventsTracking

        FEEDBACK_EVENT = 'ai_duo_messaging_feedback_submitted'
        SURFACE = 'slack'
        VALUE_FORMAT = /\A(?<direction>up|down):(?<workflow_id>\d+)\z/

        def execute
          return unless current_user
          return unless parsed_value && workflow

          track_internal_event(
            FEEDBACK_EVENT,
            user: current_user,
            namespace: workflow.resource_parent&.root_ancestor,
            additional_properties: {
              label: direction == 'up' ? 'thumbs_up' : 'thumbs_down',
              value: workflow.id,
              property: SURFACE
            }
          )

          open_reason_modal if direction == 'down'
        end

        private

        # Best-effort: the thumbs_down event is already recorded above, so a
        # failure to open the modal only loses the optional reason, not the vote.
        def open_reason_modal
          trigger_id = params[:trigger_id]
          return if trigger_id.blank?
          return unless slack_installation

          slack_api.open_view(
            trigger_id: trigger_id,
            view: ::Integrations::SlackInteractions::DuoFeedbackModal.new(workflow.id).build
          )
        end

        def parsed_value
          VALUE_FORMAT.match(action[:value].to_s)
        end
        strong_memoize_attr :parsed_value

        def direction
          parsed_value[:direction]
        end

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
