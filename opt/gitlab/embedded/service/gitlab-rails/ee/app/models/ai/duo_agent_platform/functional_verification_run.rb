# frozen_string_literal: true

module Ai
  module DuoAgentPlatform
    class FunctionalVerificationRun < ApplicationRecord
      self.table_name = 'duo_agent_platform_functional_verification_runs'

      CHECK_TYPES = { agentic_chat: 0 }.freeze
      STATUSES = { running: 0, passed: 1, failed: 2 }.freeze

      MAX_MESSAGE_LENGTH = 1024

      enum :check_type, CHECK_TYPES
      enum :status, STATUSES

      validates :check_type, presence: true, uniqueness: true
      validates :workflow_id, uniqueness: { allow_nil: true }
      validates :message, length: { maximum: MAX_MESSAGE_LENGTH }
      validates :message, presence: true, if: :failed?

      def self.current_for(check_type)
        find_by(check_type: check_type)
      end

      def self.current_for_workflow(workflow_id)
        find_by(workflow_id: workflow_id)
      end

      def self.start_run(check_type, workflow_id:)
        find_or_initialize_by(check_type: check_type).tap do |run|
          run.update!(status: :running, message: nil, workflow_id: workflow_id)
        end
      end

      def self.complete_run(check_type:, workflow_id:, status:, message:)
        raise ArgumentError, 'message is required when status is failed' if status.to_s == 'failed' && message.blank?

        where(check_type: check_type, workflow_id: workflow_id, status: :running).update_all(
          status: statuses.fetch(status.to_s),
          message: message.presence&.truncate(MAX_MESSAGE_LENGTH),
          updated_at: Time.current
        ) > 0
      end
    end
  end
end
