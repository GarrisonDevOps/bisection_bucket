# frozen_string_literal: true

module Integrations
  module SlackInteractions
    # Builds the Block Kit modal shown when a user marks a Duo response as
    # not helpful in Slack. Collects a structured reason plus an optional
    # free-text comment. The workflow ID travels in `private_metadata` so the
    # `view_submission` payload is self-contained.
    class DuoFeedbackModal
      CALLBACK_ID = 'duo_feedback_modal'
      REASON_BLOCK_ID = 'duo_feedback_reason'
      REASON_ACTION_ID = 'reason'
      COMMENT_BLOCK_ID = 'duo_feedback_comment'
      COMMENT_ACTION_ID = 'comment'
      COMMENT_MAX_LENGTH = 1000
      REASON_OTHER = 'other'

      # Returned as a `response_action: update` on view_submission so the
      # modal shows a confirmation instead of silently closing.
      def self.thanks_view
        {
          type: 'modal',
          title: { type: 'plain_text', text: s_('DuoSlack|Share feedback') },
          close: { type: 'plain_text', text: s_('DuoSlack|Done') },
          blocks: [{
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: s_('DuoSlack|*Feedback submitted.* Thanks for helping us improve GitLab Duo.')
            }
          }]
        }
      end

      def initialize(workflow_id)
        @workflow_id = workflow_id
      end

      def build
        {
          type: 'modal',
          callback_id: CALLBACK_ID,
          private_metadata: workflow_id.to_s,
          title: { type: 'plain_text', text: s_('DuoSlack|Share feedback') },
          submit: { type: 'plain_text', text: s_('DuoSlack|Submit') },
          close: { type: 'plain_text', text: s_('DuoSlack|Cancel') },
          blocks: [reason_block, comment_block, disclaimer_block]
        }
      end

      private

      attr_reader :workflow_id

      def reason_block
        {
          type: 'input',
          block_id: REASON_BLOCK_ID,
          label: { type: 'plain_text', text: s_('DuoSlack|What went wrong?') },
          element: {
            type: 'radio_buttons',
            action_id: REASON_ACTION_ID,
            options: reason_options
          }
        }
      end

      def reason_options
        [
          reason_option('incorrect', s_('DuoSlack|Incorrect or misleading')),
          reason_option('did_not_follow_instructions', s_("DuoSlack|Didn't do what I asked")),
          reason_option('incomplete', s_('DuoSlack|Incomplete')),
          reason_option(REASON_OTHER, s_('DuoSlack|Other'))
        ]
      end

      def reason_option(value, text)
        { value: value, text: { type: 'plain_text', text: text } }
      end

      def comment_block
        {
          type: 'input',
          block_id: COMMENT_BLOCK_ID,
          optional: true,
          label: { type: 'plain_text', text: s_('DuoSlack|Tell us more') },
          element: {
            type: 'plain_text_input',
            action_id: COMMENT_ACTION_ID,
            multiline: true,
            max_length: COMMENT_MAX_LENGTH,
            placeholder: {
              type: 'plain_text',
              text: s_('DuoSlack|What did you expect to happen?')
            }
          }
        }
      end

      def disclaimer_block
        {
          type: 'context',
          elements: [{
            type: 'plain_text',
            text: s_("DuoSlack|This feedback helps us improve Duo. We'll share your feedback " \
              'and the related session with GitLab.')
          }]
        }
      end
    end
  end
end
