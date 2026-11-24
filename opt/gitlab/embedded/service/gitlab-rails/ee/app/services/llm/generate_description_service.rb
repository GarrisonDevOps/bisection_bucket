# frozen_string_literal: true

module Llm
  class GenerateDescriptionService < BaseService
    extend ::Gitlab::Utils::Override

    SUPPORTED_ISSUABLE_TYPES = %w[issue work_item].freeze

    override :valid
    def valid?
      super && Ability.allowed?(user, :generate_description, resource)
    end

    private

    def ai_action
      :generate_description
    end

    def perform
      schedule_completion_worker
    end
  end
end
