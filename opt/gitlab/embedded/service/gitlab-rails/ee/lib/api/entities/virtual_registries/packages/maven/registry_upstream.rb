# frozen_string_literal: true

module API
  module Entities
    module VirtualRegistries
      module Packages
        module Maven
          class RegistryUpstream < Grape::Entity
            expose :id, documentation: { type: 'Integer' }
            expose :position, documentation: { type: 'Integer' }
            expose :registry_id, documentation: { type: 'Integer' },
              unless: ->(_, options) { options[:exclude_registry_id] }
            expose :upstream_id, documentation: { type: 'Integer' },
              unless: ->(_, options) { options[:exclude_upstream_id] }
            expose :local_upstream_id, documentation: { type: 'Integer', example: 1 }
          end
        end
      end
    end
  end
end
