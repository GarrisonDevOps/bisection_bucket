# frozen_string_literal: true

module API
  module Entities
    module VirtualRegistries
      module Container
        class Upstream < Grape::Entity
          expose :id, documentation: { type: 'Integer' }
          expose :name, documentation: { type: 'String' }
          expose :description, documentation: { type: 'String' }
          expose :group_id, documentation: { type: 'Integer' }
          expose :url, documentation: { type: 'String' }
          expose :username, documentation: { type: 'String' }
          expose :cache_validity_hours, documentation: { type: 'Integer' }
          expose :created_at, documentation: { type: 'DateTime' }
          expose :updated_at, documentation: { type: 'DateTime' }
          expose :registry_upstream,
            if: ->(_upstream, options) { options[:with_registry_upstream] },
            using: ::API::Entities::VirtualRegistries::Container::RegistryUpstream
          expose :registry_upstreams,
            if: ->(_upstream, options) { options[:with_registry_upstreams] },
            using: ::API::Entities::VirtualRegistries::Container::RegistryUpstream, documentation: { is_array: true }

          private

          # When with_registry_upstream option is true, it's guaranteed
          # that the object.registry_upstreams is a one-element array.
          def registry_upstream
            object.registry_upstreams.first
          end
        end
      end
    end
  end
end
