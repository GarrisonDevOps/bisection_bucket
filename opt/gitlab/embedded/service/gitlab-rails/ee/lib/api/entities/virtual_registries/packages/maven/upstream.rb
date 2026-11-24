# frozen_string_literal: true

module API
  module Entities
    module VirtualRegistries
      module Packages
        module Maven
          class Upstream < Grape::Entity
            expose :id, documentation: { type: 'Integer' }
            expose :name, documentation: { type: 'String' }
            expose :description, documentation: { type: 'String' }
            expose :group_id, documentation: { type: 'Integer' }
            expose :cache_validity_hours, documentation: { type: 'Integer' }
            expose :metadata_cache_validity_hours, documentation: { type: 'Integer' }
            expose :created_at, documentation: { type: 'DateTime' }
            expose :updated_at, documentation: { type: 'DateTime' }
            expose :upstream_type, documentation: { type: 'String' }

            expose :url, documentation: { type: 'String' }, if: ->(upstream, _) { upstream.remote? }
            expose :username, documentation: { type: 'String' }, if: ->(upstream, _) { upstream.remote? }

            expose :local_group_id, documentation: { type: 'Integer', example: 1 },
              if: ->(upstream, _) { upstream.local? }
            expose :local_project_id, documentation: { type: 'Integer', example: 1 },
              if: ->(upstream, _) { upstream.local? }

            expose :registry_upstream,
              if: ->(_upstream, options) { options[:with_registry_upstream] },
              using: ::API::Entities::VirtualRegistries::Packages::Maven::RegistryUpstream
            expose :registry_upstreams,
              if: ->(_upstream, options) { options[:with_registry_upstreams] },
              using: ::API::Entities::VirtualRegistries::Packages::Maven::RegistryUpstream, documentation: { is_array: true }

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
end
