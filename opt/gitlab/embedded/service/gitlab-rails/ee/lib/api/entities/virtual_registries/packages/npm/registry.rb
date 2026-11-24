# frozen_string_literal: true

module API
  module Entities
    module VirtualRegistries
      module Packages
        module Npm
          class Registry < Grape::Entity
            expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
            expose :name, documentation: { type: 'String', example: 'my-npm-registry' }
            expose :description, documentation: { type: 'String', example: 'NPM virtual registry' }
            expose :group_id, documentation: { type: 'Integer', format: 'int64', example: 1 }
            expose :created_at, documentation: { type: 'DateTime', example: '2025-12-16T13:25:30.029Z' }
            expose :updated_at, documentation: { type: 'DateTime', example: '2025-12-16T13:25:30.029Z' }
            expose :registry_upstreams,
              if: ->(_registry, options) { options[:with_registry_upstreams] },
              using: ::API::Entities::VirtualRegistries::Packages::Npm::RegistryUpstream,
              documentation: { is_array: true }
          end
        end
      end
    end
  end
end
