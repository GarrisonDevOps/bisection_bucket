# frozen_string_literal: true

module RemoteDevelopment
  class WorkspaceAgentkState < ApplicationRecord
    belongs_to :workspace, inverse_of: :workspace_agentk_state
    belongs_to :project, inverse_of: :workspace_agentk_states

    validates :workspace_id, presence: true
    validates :project_id, presence: true
    validates :desired_config, presence: true
    validate :desired_config_must_be_array

    # Validates that desired_config is an array when present
    # @return [void]
    def desired_config_must_be_array
      return if desired_config.blank?
      return if desired_config.is_a?(Array)

      errors.add(:desired_config, "must be an array")
    end
  end
end
