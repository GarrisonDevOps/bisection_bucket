# frozen_string_literal: true

module WorkItems
  class AgentPlanContentUploader < GitlabUploader
    include ObjectStorage::Concern

    storage_location :agent_plan_content

    alias_method :upload, :model

    def store_dir
      dynamic_segment
    end

    private

    def dynamic_segment
      Gitlab::HashedPath.new('work_item_agent_plans', model.work_item_id, root_hash: model.namespace_id)
    end
  end
end
