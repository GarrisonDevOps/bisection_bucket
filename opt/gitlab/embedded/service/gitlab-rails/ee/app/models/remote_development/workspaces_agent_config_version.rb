# frozen_string_literal: true

module RemoteDevelopment
  class WorkspacesAgentConfigVersion < ApplicationRecord
    include PaperTrail::VersionConcern

    self.table_name = :workspaces_agent_config_versions
    self.sequence_name = :workspaces_agent_config_versions_id_seq

    before_save :set_project_id

    private

    # @return [void]
    def set_project_id
      self.project_id = item.project_id

      nil
    end
  end
end
