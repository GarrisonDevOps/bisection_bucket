# frozen_string_literal: true

module API
  module VirtualRegistries
    module Container
      class Upstreams < ::API::Base
        include ::API::Concerns::VirtualRegistries::Container::SharedSetup
        include ::API::Concerns::VirtualRegistries::SharedAuthentication
        include ::API::PaginationParams

        helpers do
          include ::Gitlab::Utils::StrongMemoize

          def target_group
            case route.origin
            when %r{groups/:id}
              group
            when %r{registries/:id}
              registry.group
            when %r{upstreams/:id}
              upstream.group
            end
          end

          def group
            find_group!(params[:id])
          end
          strong_memoize_attr :group

          def registry
            ::VirtualRegistries::Container::Registry.find(params[:id])
          end
          strong_memoize_attr :registry

          def upstream
            ::VirtualRegistries::Container::Upstream.find(params[:id])
          end
          strong_memoize_attr :upstream
        end

        resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          params do
            requires :id, types: [String, Integer], desc: 'The group ID or full group path. Must be a top-level group'
            use :pagination
          end

          namespace ':id/-/virtual_registries/container/upstreams' do
            route_setting :lifecycle, :experiment

            after_validation do
              bad_request!(_('only available on top-level groups.')) unless group.root?
              authorize! :read_virtual_registry, group.virtual_registry_policy_subject
            end

            desc 'List all container virtual registry upstreams for a group' do
              detail 'This feature was introduced in GitLab 18.5. \
                  This feature is behind the `container_virtual_registries` feature flag.'
              success code: 200, model: Entities::VirtualRegistries::Container::Upstream
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
            params do
              optional :upstream_name, type: String, desc: 'Return upstreams with this name'
            end
            route_setting :authorization, permissions: :read_container_virtual_registry_upstream,
              boundary_type: :group
            get do
              upstreams = ::VirtualRegistries::UpstreamsFinder.new(
                upstream_class: ::VirtualRegistries::Container::Upstream,
                group: group,
                params: declared_params.slice(:upstream_name)
              ).execute

              present paginate(upstreams), with: Entities::VirtualRegistries::Container::Upstream
            end

            desc 'Test connection to a container virtual registry upstream with provided parameters' do
              detail 'This feature was introduced in GitLab 18.9. \
                  This feature is behind the `container_virtual_registries` feature flag.'
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
              requires :url, type: String, desc: 'The URL of the container virtual registry upstream',
                allow_blank: false
              optional :username, type: String, desc: 'The username of the container virtual registry upstream'
              optional :password, type: String, desc: 'The password of the container virtual registry upstream'
              all_or_none_of :username, :password
            end
            route_setting :lifecycle, :experiment
            route_setting :authorization, permissions: :test_container_virtual_registry_upstream,
              boundary_type: :group
            post :test do
              authorize! :update_virtual_registry, group.virtual_registry_policy_subject

              upstream = ::VirtualRegistries::Container::Upstream.new(
                declared_params(include_missing: false).merge(group: group, name: 'test')
              )

              render_validation_error!(upstream) if upstream.invalid?

              status :ok
              upstream.test
            end
          end
        end

        namespace 'virtual_registries/container' do
          route_setting :lifecycle, :experiment

          namespace :registries do
            route_param :id, type: Integer, desc: 'The ID of the container virtual registry' do
              namespace :upstreams do
                desc 'List all container virtual registry upstreams for a registry' do
                  detail 'This feature was introduced in GitLab 18.5. \
                      This feature is behind the `container_virtual_registries` feature flag.'
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
                route_setting :authorization, permissions: :read_container_virtual_registry_upstream,
                  boundary: -> { registry.group }, boundary_type: :group
                get do
                  authorize! :read_virtual_registry, registry

                  present ::VirtualRegistries::Container::Upstream.eager_load_registry_upstream(registry:),
                    with: Entities::VirtualRegistries::Container::Upstream,
                    with_registry_upstream: true, exclude_upstream_id: true
                end

                desc 'Add a container virtual registry upstream' do
                  detail 'This feature was introduced in GitLab 18.5. \
                      This feature is behind the `container_virtual_registries` feature flag.'
                  success code: 201, model: ::API::Entities::VirtualRegistries::Container::Upstream
                  failure [
                    { code: 400, message: 'Bad Request' },
                    { code: 401, message: 'Unauthorized' },
                    { code: 403, message: 'Forbidden' },
                    { code: 404, message: 'Not found' },
                    { code: 409, message: 'Conflict' }
                  ]
                  tags %w[virtual_registries]
                  hidden true
                end
                params do
                  requires :url, type: String, desc: 'The URL of the container virtual registry upstream',
                    allow_blank: false
                  requires :name, type: String, desc: 'The name of the container virtual registry upstream',
                    allow_blank: false
                  optional :description, type: String,
                    desc: 'The description of the container virtual registry upstream'
                  optional :username, type: String, desc: 'The username of the container virtual registry upstream'
                  optional :password, type: String, desc: 'The password of the container virtual registry upstream'
                  optional :cache_validity_hours, type: Integer, default: 24, values: 0..,
                    desc: 'The cache validity in hours.'
                  all_or_none_of :username, :password
                end

                route_setting :authorization, permissions: :create_container_virtual_registry_upstream,
                  boundary: -> { registry.group }, boundary_type: :group
                post do
                  authorize! :create_virtual_registry, registry

                  new_upstream = registry.upstreams.create(
                    declared_params(include_missing: false).merge(group: registry.group)
                  )

                  render_validation_error!(new_upstream) unless new_upstream.persisted?

                  present new_upstream, with: Entities::VirtualRegistries::Container::Upstream,
                    with_registry_upstream: true, exclude_upstream_id: true
                end
              end
            end
          end

          namespace :upstreams do
            route_param :id, type: Integer, desc: 'The ID of the container virtual registry upstream' do
              desc 'Get a specific container virtual registry upstream' do
                detail 'This feature was introduced in GitLab 18.5. \
                      This feature is behind the `container_virtual_registries` feature flag.'
                success ::API::Entities::VirtualRegistries::Container::Upstream
                failure [
                  { code: 400, message: 'Bad Request' },
                  { code: 401, message: 'Unauthorized' },
                  { code: 403, message: 'Forbidden' },
                  { code: 404, message: 'Not found' }
                ]
                tags %w[virtual_registries]
                hidden true
              end
              route_setting :authorization, permissions: :read_container_virtual_registry_upstream,
                boundary: -> { upstream.group }, boundary_type: :group
              get do
                authorize! :read_virtual_registry, upstream

                present upstream, with: ::API::Entities::VirtualRegistries::Container::Upstream,
                  with_registry_upstreams: true, exclude_upstream_id: true
              end

              desc 'Update a container virtual registry upstream' do
                detail 'This feature was introduced in GitLab 18.5. \
                      This feature is behind the `container_virtual_registries` feature flag.'
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
                optional :name, type: String, desc: 'The name of the container virtual registry upstream',
                  allow_blank: false
                optional :description, type: String, desc: 'The description of the container virtual registry upstream'
                optional :url, type: String, desc: 'The URL of the container virtual registry upstream',
                  allow_blank: false
                optional :username, type: String, desc: 'The username of the container virtual registry upstream'
                optional :password, type: String, desc: 'The password of the container virtual registry upstream'
                optional :cache_validity_hours, type: Integer, desc: 'The validity of the cache in hours'

                at_least_one_of :name, :description, :url, :username, :password, :cache_validity_hours
              end
              route_setting :authorization, permissions: :update_container_virtual_registry_upstream,
                boundary: -> { upstream.group }, boundary_type: :group
              patch do
                authorize! :update_virtual_registry, upstream

                render_validation_error!(upstream) unless upstream.update(declared_params(include_missing: false))

                status :ok
              end

              desc 'Delete a container virtual registry upstream' do
                detail 'This feature was introduced in GitLab 18.5. \
                      This feature is behind the `container_virtual_registries` feature flag.'
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
              route_setting :authorization, permissions: :delete_container_virtual_registry_upstream,
                boundary: -> { upstream.group }, boundary_type: :group
              delete do
                authorize! :destroy_virtual_registry, upstream

                destroy_conditionally!(upstream) do
                  upstream.transaction do
                    ::VirtualRegistries::Container::RegistryUpstream
                      .sync_higher_positions(upstream.registry_upstreams)
                    upstream.destroy
                  end
                end
              end

              desc 'Purge cache for a container virtual registry upstream' do
                detail 'This feature was introduced in GitLab 18.7. \
                        This feature is behind the `container_virtual_registries` feature flag.'
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
              route_setting :authorization, permissions: :purge_container_virtual_registry_upstream_cache,
                boundary: -> { upstream.group }, boundary_type: :group
              delete :cache do
                authorize! :destroy_virtual_registry, upstream

                destroy_conditionally!(upstream) { upstream.purge_cache! }
              end

              desc 'Test connection to an existing container virtual registry upstream with optional override params' do
                detail 'This feature was introduced in GitLab 18.9. \
                      This feature is behind the `container_virtual_registries` feature flag.'
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
                optional :url, type: String, desc: 'The URL of the container virtual registry upstream',
                  allow_blank: false
                optional :username, type: String, desc: 'The username of the container virtual registry upstream'
                optional :password, type: String, desc: 'The password of the container virtual registry upstream'
              end
              route_setting :authorization, permissions: :test_container_virtual_registry_upstream,
                boundary: -> { upstream.group }, boundary_type: :group
              post :test do
                authorize! :update_virtual_registry, upstream

                params_provided = declared_params(include_missing: false)

                url_override = params_provided[:url]
                username_param = params_provided[:username]
                password_param = params_provided[:password]

                url_changed = params_provided.key?(:url) && url_override != upstream.url
                username_changed = params_provided.key?(:username) && username_param != upstream.username
                password_changed = params_provided.key?(:password) &&
                  password_param.present? && password_param != upstream.password

                credentials_changed = username_changed || password_changed

                upstream_params = {
                  url: url_changed ? url_override : upstream.url,
                  username: username_param,
                  password: password_param,
                  group: upstream.group,
                  name: 'test'
                }

                test_upstream = if url_changed || credentials_changed
                                  ::VirtualRegistries::Container::Upstream.new(**upstream_params)
                                else
                                  upstream
                                end

                render_validation_error!(test_upstream) if test_upstream != upstream && test_upstream.invalid?

                status :ok
                test_upstream.test
              end
            end
          end
        end
      end
    end
  end
end
