# frozen_string_literal: true

module API
  module VirtualRegistries
    module Packages
      module Npm
        class Registries < ::API::Base
          include ::API::Concerns::VirtualRegistries::Packages::Npm::SharedSetup
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
              ::VirtualRegistries::Packages::Npm::Registry.find(params[:id])
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

            namespace ':id/-/virtual_registries/packages/npm/registries' do
              route_setting :lifecycle, :experiment

              desc 'Get the list of all npm virtual registries' do
                detail 'This feature was introduced in GitLab 18.10. \
                    This feature is behind the `npm_virtual_registry` feature flag.'
                success ::API::Entities::VirtualRegistries::Packages::Npm::Registry
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

              route_setting :authorization, permissions: :read_npm_virtual_registry, boundary_type: :group
              get do
                authorize! :read_virtual_registry, policy_subject

                registries = ::VirtualRegistries::Packages::Npm::Registry.for_group(group)

                present registries, with: ::API::Entities::VirtualRegistries::Packages::Npm::Registry
              end

              desc 'Create a new npm virtual registry' do
                detail 'This feature was introduced in GitLab 18.10. \
                    This feature is behind the `npm_virtual_registry` feature flag.'
                success ::API::Entities::VirtualRegistries::Packages::Npm::Registry
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
                requires :name, type: String, desc: 'The name of the npm virtual registry',
                  allow_blank: false
                optional :description, type: String, desc: 'The description of the npm virtual registry'
              end

              route_setting :lifecycle, :experiment
              route_setting :authorization, permissions: :create_npm_virtual_registry, boundary_type: :group
              post do
                authorize! :create_virtual_registry, policy_subject

                new_registry = ::VirtualRegistries::Packages::Npm::Registry
                  .new(declared_params(include_missing: false).merge(group:))

                render_validation_error!(new_registry) unless new_registry.save

                present new_registry, with: ::API::Entities::VirtualRegistries::Packages::Npm::Registry
              end
            end
          end

          namespace 'virtual_registries/packages/npm/registries' do
            route_setting :lifecycle, :experiment

            route_param :id, type: Integer, desc: 'The ID of the npm virtual registry' do
              desc 'Get a specific npm virtual registry' do
                detail 'This feature was introduced in GitLab 18.10. \
                  This feature is behind the `npm_virtual_registry` feature flag.'
                success ::API::Entities::VirtualRegistries::Packages::Npm::Registry
                failure [
                  { code: 400, message: 'Bad request' },
                  { code: 401, message: 'Unauthorized' },
                  { code: 403, message: 'Forbidden' },
                  { code: 404, message: 'Not found' }
                ]
                tags %w[virtual_registries]
                hidden true
              end
              route_setting :authorization,
                permissions: :read_npm_virtual_registry,
                boundary: -> { registry.group },
                boundary_type: :group
              get do
                authorize! :read_virtual_registry, registry

                present registry, with: Entities::VirtualRegistries::Packages::Npm::Registry,
                  with_registry_upstreams: true, exclude_registry_id: true
              end

              desc 'Update a specific npm virtual registry' do
                detail 'This feature was introduced in GitLab 18.10. \
                        This feature is behind the `npm_virtual_registry` feature flag.'
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
                  optional :name, type: String, desc: 'The name of the npm virtual registry'
                  optional :description, type: String, desc: 'The description of the npm virtual registry'
                end

                at_least_one_of :name, :description
              end
              route_setting :authorization,
                permissions: :update_npm_virtual_registry,
                boundary: -> { registry.group },
                boundary_type: :group
              patch do
                authorize! :update_virtual_registry, registry

                render_validation_error!(registry) unless registry.update(declared_params(include_missing: false))

                status :ok
              end

              desc 'Delete a specific npm virtual registry' do
                detail 'This feature was introduced in GitLab 18.10. \
                  This feature is behind the `npm_virtual_registry` feature flag.'
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

              route_setting :authorization,
                permissions: :delete_npm_virtual_registry,
                boundary: -> { registry.group },
                boundary_type: :group
              delete do
                authorize! :destroy_virtual_registry, registry

                destroy_conditionally!(registry)
              end

              desc 'Purge cache for a npm virtual registry' do
                detail 'This feature was introduced in GitLab 18.10. \
                        This feature is behind the `npm_virtual_registry` feature flag.'
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

              route_setting :authorization,
                permissions: :purge_npm_virtual_registry_cache,
                boundary: -> { registry.group },
                boundary_type: :group
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
