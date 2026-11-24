# frozen_string_literal: true

module API
  module VirtualRegistries
    module Packages
      module Maven
        class RegistryUpstreams < ::API::Base
          include ::API::Concerns::VirtualRegistries::Packages::Maven::SharedSetup
          include ::API::Concerns::VirtualRegistries::SharedAuthentication

          helpers do
            include ::Gitlab::Utils::StrongMemoize

            def upstream
              registry_upstream.resolved_upstream
            end
            strong_memoize_attr :upstream

            def target_group
              params[:id] ? registry_upstream.group : registry.group
            end

            def registry_upstream
              ::VirtualRegistries::Packages::Maven::RegistryUpstream.find(params[:id])
            end
            strong_memoize_attr :registry_upstream

            def registry
              ::VirtualRegistries::Packages::Maven::Registry.find(params[:registry_id])
            end
            strong_memoize_attr :registry
          end

          namespace 'virtual_registries/packages/maven' do
            route_setting :lifecycle, :experiment

            namespace :registry_upstreams do
              desc 'Associates an upstream with a registry' do
                detail 'This feature was introduced in GitLab 18.1. \
                  This feature behind the `maven_virtual_registry` feature flag.'
                success code: 201, model: Entities::VirtualRegistries::Packages::Maven::RegistryUpstream
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
                requires :registry_id, type: Integer, allow_blank: false, desc: 'The ID of the maven registry'
                optional :upstream_id, type: Integer, allow_blank: false, desc: 'The ID of the maven upstream'
                optional :local_upstream_id, type: Integer, allow_blank: false,
                  desc: 'The ID of the maven local upstream'
                exactly_one_of :upstream_id, :local_upstream_id
              end
              route_setting :authorization, permissions: :associate_maven_virtual_registry_upstream,
                boundary: -> { registry.group }, boundary_type: :group
              post do
                authorize! :create_virtual_registry, registry

                id_param = params[:local_upstream_id] ? :local_upstream_id : :upstream_id
                upstream_class = UPSTREAM_CLASSES.fetch(id_param)

                if upstream_class.for_id_and_group(id: params[id_param], group: registry.group).none?
                  not_found!('Upstream')
                end

                registry_upstream = ::VirtualRegistries::Packages::Maven::RegistryUpstream.new(declared_params)
                render_validation_error!(registry_upstream) unless registry_upstream.save

                present registry_upstream, with: Entities::VirtualRegistries::Packages::Maven::RegistryUpstream
              end

              route_param :id, type: Integer, desc: 'The ID of the maven virtual registry upstream' do
                desc 'Update an upstream within a specific maven virtual registry' do
                  detail 'This feature was introduced in GitLab 18.0. \
                      This feature behind the `maven_virtual_registry` feature flag.'
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
                    desc: 'The priority order of an upstream within a maven virtual registry'
                end
                route_setting :lifecycle, :experiment
                route_setting :authorization, permissions: :update_maven_virtual_registry_upstream,
                  boundary: -> { upstream.group }, boundary_type: :group
                patch do
                  authorize! :update_virtual_registry, upstream

                  registry_upstream.update_position(params[:position])

                  status :ok
                end

                desc 'Disassociates an upstream from a registry' do
                  detail 'This feature was introduced in GitLab 18.1. \
                  This feature behind the `maven_virtual_registry` feature flag.'
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
                route_setting :authorization, permissions: :disassociate_maven_virtual_registry_upstream,
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
end
