# frozen_string_literal: true

module API
  module Entities
    module Ai
      module DuoWorkflows
        class Workflow
          class AgentPrivileges < Grape::Entity
            expose :all_privileges, documentation: { type: 'Hash', is_array: true }

            def all_privileges
              object::ALL_PRIVILEGES.map do |id, attributes|
                {
                  id: id,
                  name: attributes[:name],
                  description: attributes[:description],
                  default_enabled: id.in?(object::DEFAULT_PRIVILEGES)
                }
              end
            end
          end
        end
      end
    end
  end
end
