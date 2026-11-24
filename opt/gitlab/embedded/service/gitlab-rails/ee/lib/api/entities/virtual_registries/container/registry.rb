# frozen_string_literal: true

module API
  module Entities
    module VirtualRegistries
      module Container
        class Registry < Grape::Entity
          expose :id, documentation: { type: 'Integer' }
          expose :name, documentation: { type: 'String' }
          expose :description, documentation: { type: 'String' }
          expose :group_id, documentation: { type: 'Integer' }
          expose :created_at, documentation: { type: 'DateTime' }
          expose :updated_at, documentation: { type: 'DateTime' }
          expose :registry_upstreams,
            if: ->(_registry, options) { options[:with_registry_upstreams] },
            using: ::API::Entities::VirtualRegistries::Container::RegistryUpstream, documentation: { is_array: true }
        end
      end
    end
  end
end
