# frozen_string_literal: true

module API
  module Entities
    class ProjectScopeLink < Grape::Entity
      expose :source_project_id, documentation: {
        type: 'Integer', format: 'int64', desc: 'ID of the project whose job token inbound allowlist is updated.'
      }
      expose :target_project_id, documentation: {
        type: 'Integer', format: 'int64', desc: "ID of the project added to the source project's inbound allowlist."
      }
    end
  end
end
