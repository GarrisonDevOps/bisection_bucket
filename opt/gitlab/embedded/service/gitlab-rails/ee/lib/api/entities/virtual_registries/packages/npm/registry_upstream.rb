# frozen_string_literal: true

module API
  module Entities
    module VirtualRegistries
      module Packages
        module Npm
          class RegistryUpstream < Grape::Entity
            expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
            expose :position, documentation: { type: 'Integer', example: 1 }
            expose :registry_id,
              unless: ->(_, options) { options[:exclude_registry_id] },
              documentation: { type: 'Integer', format: 'int64', example: 1 }
            expose :upstream_id,
              unless: ->(_, options) { options[:exclude_upstream_id] },
              documentation: { type: 'Integer', format: 'int64', example: 1 }
          end
        end
      end
    end
  end
end
