# frozen_string_literal: true

module Integrations
  module SlackInteractions
    # Handles submission of the Duo feedback reason modal
    # (DuoFeedbackModal). The thumbs_down vote was already
    # recorded when the button was clicked (SlackBlockActions::DuoFeedbackHandler);
    # this appends
    # a second event enriched with the selected reason and optional comment.
    class DuoFeedbackModalSubmitService
      include Gitlab::InternalEventsTracking
      include Gitlab::Utils::StrongMemoize

      def initialize(params)
        @params = params
        @team_id = params.dig(:team, :id)
        @slack_user_id = params.dig(:user, :id)
      end

      def execute
        return ServiceResponse.success unless current_user && workflow && reason
        return comment_required_response if reason == DuoFeedbackModal::REASON_OTHER && comment.blank?

        track_internal_event(
          SlackBlockActions::DuoFeedbackHandler::FEEDBACK_EVENT,
          user: current_user,
          namespace: workflow.resource_parent&.root_ancestor,
          additional_properties: {
            label: 'thumbs_down',
            value: workflow.id,
            property: SlackBlockActions::DuoFeedbackHandler::SURFACE,
            reason: reason,
            comment: comment
          }.compact
        )

        ServiceResponse.success(payload: {
          response_action: 'update',
          view: DuoFeedbackModal.thanks_view
        })
      end

      private

      attr_reader :params, :team_id, :slack_user_id

      # Slack renders this as an inline validation error on the comment block.
      def comment_required_response
        ServiceResponse.success(payload: {
          response_action: 'errors',
          errors: {
            DuoFeedbackModal::COMMENT_BLOCK_ID => s_('DuoSlack|Tell us what went wrong.')
          }
        })
      end

      def values
        params.dig(:view, :state, :values) || {}
      end

      def state_value(block_id, action_id, *keys)
        values.dig(block_id.to_sym, action_id.to_sym, *keys)
      end

      def reason
        state_value(
          DuoFeedbackModal::REASON_BLOCK_ID, DuoFeedbackModal::REASON_ACTION_ID,
          :selected_option, :value
        )
      end

      def comment
        state_value(DuoFeedbackModal::COMMENT_BLOCK_ID, DuoFeedbackModal::COMMENT_ACTION_ID, :value)
          &.first(DuoFeedbackModal::COMMENT_MAX_LENGTH)&.presence
      end

      def workflow
        workflow_id = params.dig(:view, :private_metadata).to_s
        return unless /\A\d+\z/.match?(workflow_id)

        ::Ai::DuoWorkflows::Workflow.find_by_id(workflow_id)
      end
      strong_memoize_attr :workflow

      def current_user
        ChatNames::FindUserService.new(team_id, slack_user_id).execute&.user
      end
      strong_memoize_attr :current_user
    end
  end
end
