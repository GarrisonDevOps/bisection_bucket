# frozen_string_literal: true

module API
  module VirtualRegistries
    module Packages
      module Maven
        class Registries < ::API::Base
          include ::API::Concerns::VirtualRegistries::Packages::Maven::SharedSetup
          include ::API::Concerns::VirtualRegistries::SharedAuthentication

          helpers do
            include ::Gitlab::Utils::StrongMemoize

            def target_group
              request.path.include?('/groups') ? group : registry.group
            end

            def group
              find_group!(params[:id])
            end
            strong_memoize_attr :group

            def registry
              ::VirtualRegistries::Packages::Maven::Registry.find(params[:id])
            end
            strong_memoize_attr :registry

            def policy_subject
              group.virtual_registry_policy_subject
            end
          end

          resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
            params do
              requires :id, types: [String, Integer], desc: 'The group ID or full group path. Must be a top-level group'
            end

            namespace ':id/-/virtual_registries/packages/maven/registries' do
              route_setting :lifecycle, :experiment

              desc 'Get the list of all maven virtual registries' do
                detail 'This feature was introduced in GitLab 17.4. \
                    This feature is behind the `maven_virtual_registry` feature flag.'
                success ::API::Entities::VirtualRegistries::Packages::Maven::Registry
                is_array true
                failure [
                  { code: 400, message: 'Bad Request' },
                  { code: 401, message: 'Unauthorized' },
                  { code: 403, message: 'Forbidden' },
                  { code: 404, message: 'Not found' }
                ]
                tags %w[virtual_registries]
                hidden true
              end

              route_setting :authorization, permissions: :read_maven_virtual_registry, boundary_type: :group
              get do
                authorize! :read_virtual_registry, policy_subject

                registries = ::VirtualRegistries::Packages::Maven::Registry.for_group(group)

                present registries, with: ::API::Entities::VirtualRegistries::Packages::Maven::Registry
              end

              desc 'Create a new maven virtual registry' do
                detail 'This feature was introduced in GitLab 17.4. \
                    This feature is behind the `maven_virtual_registry` feature flag.'
                success ::API::Entities::VirtualRegistries::Packages::Maven::Registry
                failure [
                  { code: 400, message: 'Bad request' },
                  { code: 401, message: 'Unauthorized' },
                  { code: 403, message: 'Forbidden' },
                  { code: 404, message: 'Not found' }
                ]
                tags %w[virtual_registries]
                hidden true
              end

              params do
                requires :name, type: String, desc: 'The name of the maven virtual registry',
                  allow_blank: false
                optional :description, type: String, desc: 'The description of the maven virtual registry'
              end
              route_setting :lifecycle, :experiment
              route_setting :authorization, permissions: :create_maven_virtual_registry, boundary_type: :group
              post do
                authorize! :create_virtual_registry, policy_subject

                new_reg = ::VirtualRegistries::Packages::Maven::Registry
                            .new(declared_params(include_missing: false).merge(group:))

                render_validation_error!(new_reg) unless new_reg.save

                present new_reg, with: ::API::Entities::VirtualRegistries::Packages::Maven::Registry
              end
            end
          end

          namespace 'virtual_registries/packages/maven/registries' do
            route_setting :lifecycle, :experiment

            route_param :id, type: Integer, desc: 'The ID of the maven virtual registry' do
              desc 'Get a specific maven virtual registry' do
                detail 'This feature was introduced in GitLab 17.4. \
                  This feature is behind the `maven_virtual_registry` feature flag.'
                success ::API::Entities::VirtualRegistries::Packages::Maven::Registry
                failure [
                  { code: 400, message: 'Bad request' },
                  { code: 401, message: 'Unauthorized' },
                  { code: 403, message: 'Forbidden' },
                  { code: 404, message: 'Not found' }
                ]
                tags %w[virtual_registries]
                hidden true
              end
              route_setting :authorization, permissions: :read_maven_virtual_registry, boundary: -> { registry.group },
                boundary_type: :group
              get do
                authorize! :read_virtual_registry, registry

                present registry, with: Entities::VirtualRegistries::Packages::Maven::Registry,
                  with_registry_upstreams: true, exclude_registry_id: true
              end

              desc 'Update a specific maven virtual registry' do
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
                with(allow_blank: false) do
                  optional :name, type: String, desc: 'The name of the maven virtual registry'
                  optional :description, type: String, desc: 'The description of the maven virtual registry'
                end

                at_least_one_of :name, :description
              end
              route_setting :authorization, permissions: :update_maven_virtual_registry,
                boundary: -> { registry.group }, boundary_type: :group
              patch do
                authorize! :update_virtual_registry, registry

                render_validation_error!(registry) unless registry.update(declared_params(include_missing: false))

                status :ok
              end

              desc 'Delete a specific maven virtual registry' do
                detail 'This feature was introduced in GitLab 17.4. \
                  This feature is behind the `maven_virtual_registry` feature flag.'
                success code: 204
                failure [
                  { code: 400, message: 'Bad request' },
                  { code: 401, message: 'Unauthorized' },
                  { code: 403, message: 'Forbidden' },
                  { code: 404, message: 'Not found' },
                  { code: 412, message: 'Precondition Failed' }
                ]
                tags %w[virtual_registries]
                hidden true
              end
              route_setting :authorization, permissions: :delete_maven_virtual_registry,
                boundary: -> { registry.group }, boundary_type: :group
              delete do
                authorize! :destroy_virtual_registry, registry

                destroy_conditionally!(registry)
              end

              desc 'Purge cache for a maven virtual registry' do
                detail 'This feature was introduced in GitLab 18.2. \
                        This feature is behind the `maven_virtual_registry` feature flag.'
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
              route_setting :authorization, permissions: :purge_maven_virtual_registry_cache,
                boundary: -> { registry.group }, boundary_type: :group
              delete :cache do
                authorize! :destroy_virtual_registry, registry

                destroy_conditionally!(registry) { registry.purge_cache! }
              end
            end
          end
        end
      end
    end
  end
end
