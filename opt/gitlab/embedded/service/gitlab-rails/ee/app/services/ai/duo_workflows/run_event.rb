# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Validates the plain-hash event a run starts or continues with; the hash
    # crosses Sidekiq as JSON, so this stays a wrapper, not a value object. The
    # types key off the session's awaiting-state rather than its status list, so
    # a new awaiting-state extends the session model, not this class.
    class RunEvent
      INPUT_KEYS = %w[text type].freeze
      APPROVAL_KEYS = %w[approved message type].freeze
      APPROVAL_REQUIRED_KEYS = %w[approved type].freeze

      APPROVED_REPLY = 'Approved. Continue.'
      REJECTED_REPLY = 'Rejected. Do not proceed.'
      APPROVAL_WITH_MESSAGE_ERROR = 'human_message cannot be sent with human_approval=true. Approve without a ' \
        'message, or reject with human_approval=false and human_message.'

      # A flow's question routes on the decision (a rejection with a message is the reply), so
      # only a chat turn takes the reply as the next message.
      #
      # @param workflow [Ai::DuoWorkflows::Workflow] the paused session
      # @param approved [Boolean] the user's decision
      # @param message [String, nil] the user's reply or rejection reason
      # @return [Hash] an input or approval event
      def self.for_resume(workflow, approved:, message:)
        if awaits_next_message?(workflow)
          return { type: :input, text: message.presence || (approved ? APPROVED_REPLY : REJECTED_REPLY) }
        end

        { type: :approval, approved: approved, message: message }.compact
      end

      # A chat agent at input_required waits for the user's next message, not for a decision.
      def self.awaits_next_message?(workflow)
        workflow.chat? && workflow.input_required?
      end
      private_class_method :awaits_next_message?

      def initialize(event)
        @event = event.stringify_keys if event.is_a?(Hash)
      end

      def valid_for?(workflow)
        return false unless event

        (input? && (workflow.created? || workflow.input_required?)) ||
          (approval? && (workflow.awaiting_approval? || workflow.input_required?))
      end

      # `text` is not always prose: code_review/v1 passes an MR iid that gets
      # unpacked downstream. The type name stays neutral so that stays visible.
      def input?
        event_type == 'input' && event.keys.sort == INPUT_KEYS && event['text'].is_a?(String) &&
          event['text'].present?
      end

      # Tool and plan approval carry the identical payload, hence one type.
      def approval?
        event_type == 'approval' && (event.keys - APPROVAL_KEYS).empty? &&
          (APPROVAL_REQUIRED_KEYS - event.keys).empty? &&
          [true, false].include?(event['approved']) && (event['message'].nil? || event['message'].is_a?(String))
      end

      def approval_with_message?
        approval? && approved? && message.present?
      end

      def text
        event['text']
      end

      def approved?
        event['approved']
      end

      def message
        event['message']
      end

      # String keys: this hash crosses the Sidekiq boundary and lands in the
      # Workhorse request body as JSON either way.
      def workhorse_approval
        return { 'approval' => {} } if approved?

        { 'rejection' => { 'message' => message } }
      end

      private

      attr_reader :event

      def event_type
        event['type'].to_s
      end
    end
  end
end
