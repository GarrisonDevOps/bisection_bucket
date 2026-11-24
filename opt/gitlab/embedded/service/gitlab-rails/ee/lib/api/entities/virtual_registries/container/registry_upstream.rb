# frozen_string_literal: true

module API
  module Entities
    module VirtualRegistries
      module Container
        class RegistryUpstream < Grape::Entity
          expose :id, documentation: { type: 'Integer' }
          expose :position, documentation: { type: 'Integer' }
          expose :registry_id, documentation: { type: 'Integer' },
            unless: ->(_, options) { options[:exclude_registry_id] }
          expose :upstream_id, documentation: { type: 'Integer' },
            unless: ->(_, options) { options[:exclude_upstream_id] }
        end
      end
    end
  end
end
