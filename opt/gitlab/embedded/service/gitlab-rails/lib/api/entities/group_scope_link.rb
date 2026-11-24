# frozen_string_literal: true

module API
  module Entities
    class GroupScopeLink < Grape::Entity
      expose :source_project_id, documentation: {
        type: 'Integer', format: 'int64', desc: 'ID of the project whose CI/CD job token allowlist includes the group.'
      }
      expose :target_group_id, documentation: {
        type: 'Integer', format: 'int64', desc: 'ID of the group added to the allowlist.'
      }
    end
  end
end
