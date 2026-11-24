# frozen_string_literal: true

module API
  module VirtualRegistries
    module Container
      class RegistryUpstreams < ::API::Base
        include ::API::Concerns::VirtualRegistries::Container::SharedSetup
        include ::API::Concerns::VirtualRegistries::SharedAuthentication

        helpers do
          include ::Gitlab::Utils::StrongMemoize

          delegate :upstream, to: :registry_upstream

          def target_group
            params[:id] ? registry_upstream.group : registry.group
          end

          def registry_upstream
            ::VirtualRegistries::Container::RegistryUpstream.find(params[:id])
          end
          strong_memoize_attr :registry_upstream

          def registry
            ::VirtualRegistries::Container::Registry.find(params[:registry_id])
          end
          strong_memoize_attr :registry
        end

        namespace 'virtual_registries/container' do
          route_setting :lifecycle, :experiment

          namespace :registry_upstreams do
            desc 'Associates an upstream with a registry' do
              detail 'This feature was introduced in GitLab 18.6. \
                This feature behind the `container_virtual_registries` feature flag.'
              success code: 201, model: Entities::VirtualRegistries::Container::RegistryUpstream
              failure [
                { code: 400, message: 'Bad Request' },
                { code: 401, message: 'Unauthorized' },
                { code: 403, message: 'Forbidden' },
                { code: 404, message: 'Not found' }
              ]
              tags %w[virtual_registries]
              hidden true
            end

            params do
              # rubocop:disable API/ParameterType -- false positive: `with(type:)` block applies type to all params inside; cop does not recognise this pattern
              with(type: Integer, allow_blank: false) do
                requires :registry_id, desc: 'The ID of the registry'
                requires :upstream_id, desc: 'The ID of the upstream'
              end
              # rubocop:enable API/ParameterType
            end

            route_setting :authorization, permissions: :associate_container_virtual_registry_upstream,
              boundary: -> { registry.group }, boundary_type: :group
            post do
              authorize! :create_virtual_registry, registry

              if ::VirtualRegistries::Container::Upstream.for_id_and_group(id: params[:upstream_id],
                group: registry.group).none?
                not_found!('Upstream')
              end

              registry_upstream = ::VirtualRegistries::Container::RegistryUpstream.new(declared_params)
              render_validation_error!(registry_upstream) unless registry_upstream.save

              present registry_upstream, with: Entities::VirtualRegistries::Container::RegistryUpstream
            end

            route_param :id, type: Integer, desc: 'The ID of the container virtual registry upstream' do
              desc 'Update an upstream within a specific container virtual registry' do
                detail 'This feature was introduced in GitLab 18.6. \
                    This feature behind the `container_virtual_registries` feature flag.'
                success code: 200
                failure [
                  { code: 400, message: 'Bad Request' },
                  { code: 401, message: 'Unauthorized' },
                  { code: 403, message: 'Forbidden' },
                  { code: 404, message: 'Not found' }
                ]
                tags %w[virtual_registries]
                hidden true
              end
              params do
                requires :position, type: Integer, values: 1..20,
                  desc: 'The priority order of an upstream within a container virtual registry'
              end

              route_setting :lifecycle, :experiment
              route_setting :authorization, permissions: :update_container_virtual_registry_upstream,
                boundary: -> { registry_upstream.group }, boundary_type: :group
              patch do
                authorize! :update_virtual_registry, upstream

                registry_upstream.update_position(params[:position])

                status :ok
              end

              desc 'Disassociates an upstream from a registry' do
                detail 'This feature was introduced in GitLab 18.6. \
                This feature behind the `container_virtual_registries` feature flag.'
                success code: 204
                failure [
                  { code: 400, message: 'Bad Request' },
                  { code: 401, message: 'Unauthorized' },
                  { code: 403, message: 'Forbidden' },
                  { code: 404, message: 'Not found' }
                ]
                tags %w[virtual_registries]
                hidden true
              end

              route_setting :lifecycle, :experiment
              route_setting :authorization, permissions: :disassociate_container_virtual_registry_upstream,
                boundary: -> { registry_upstream.group }, boundary_type: :group
              delete do
                authorize! :destroy_virtual_registry, upstream

                destroy_conditionally!(registry_upstream) do
                  registry_upstream.transaction do
                    registry_upstream.sync_higher_positions
                    registry_upstream.destroy
                  end
                end
              end
            end
          end
        end
      end
    end
  end
end
