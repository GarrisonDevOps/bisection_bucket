# frozen_string_literal: true

module API
  module VirtualRegistries
    module Packages
      module Maven
        class Upstreams < ::API::Base
          include ::API::Concerns::VirtualRegistries::Packages::Maven::SharedSetup
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
              when %r{local/upstreams/:id}
                local_upstream.group
              # Match `maven/upstreams/:id`, not bare `upstreams/:id`, so this can't also match the
              # local route `.../maven/local/upstreams/:id`. The two clauses stay mutually exclusive
              # regardless of their order.
              when %r{maven/upstreams/:id}
                upstream.group
              end
            end

            def group
              find_group!(params[:id])
            end
            strong_memoize_attr :group

            def registry
              ::VirtualRegistries::Packages::Maven::Registry.find(params[:id])
            end
            strong_memoize_attr :registry

            def upstream
              ::VirtualRegistries::Packages::Maven::Upstream.find(params[:id])
            end
            strong_memoize_attr :upstream

            def local_upstream
              ::VirtualRegistries::Packages::Maven::Local::Upstream.find(params[:id])
            end
            strong_memoize_attr :local_upstream

            def present_maven_upstream(upstream)
              authorize! :read_virtual_registry, upstream

              present upstream, with: ::API::Entities::VirtualRegistries::Packages::Maven::Upstream,
                with_registry_upstreams: true, exclude_upstream_id: true
            end

            def destroy_maven_upstream(upstream)
              authorize! :destroy_virtual_registry, upstream

              destroy_conditionally!(upstream) { upstream.destroy_and_sync_positions }
            end
          end

          resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
            params do
              requires :id, types: [String, Integer], desc: 'The group ID or full group path. Must be a top-level group'
              use :pagination
            end

            namespace ':id/-/virtual_registries/packages/maven/upstreams' do
              route_setting :lifecycle, :experiment

              after_validation do
                bad_request!(_('only available on top-level groups.')) unless group.root?
                authorize! :read_virtual_registry, group.virtual_registry_policy_subject
              end

              desc 'List all maven virtual registry upstreams for a group' do
                detail 'This feature was introduced in GitLab 18.3. \
                    This feature is behind the `maven_virtual_registry` feature flag.'
                success code: 200, model: Entities::VirtualRegistries::Packages::Maven::Upstream
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
              route_setting :authorization, permissions: :read_maven_virtual_registry_upstream, boundary_type: :group
              get do
                upstreams = UPSTREAM_CLASSES.values.flat_map do |klass|
                  ::VirtualRegistries::UpstreamsFinder.new(
                    upstream_class: klass, group: group, params: declared_params.slice(:upstream_name)
                  ).execute.to_a
                end

                upstreams = Kaminari.paginate_array(
                  upstreams.sort_by { |u| [u.updated_at, u.upstream_type, u.id] }.reverse
                )

                present paginate(upstreams), with: Entities::VirtualRegistries::Packages::Maven::Upstream
              end

              desc 'Test connection to a maven virtual registry upstream with provided parameters' do
                detail 'This feature was introduced in GitLab 18.3. \
                        This feature is behind the `maven_virtual_registry` feature flag.'
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
                requires :url, type: String, desc: 'The URL of the maven virtual registry upstream',
                  allow_blank: false
                optional :username, type: String, desc: 'The username of the maven virtual registry upstream'
                optional :password, type: String, desc: 'The password of the maven virtual registry upstream'
                all_or_none_of :username, :password
              end
              route_setting :lifecycle, :experiment
              route_setting :authorization, permissions: :test_maven_virtual_registry_upstream, boundary_type: :group
              post :test do
                authorize! :update_virtual_registry, group.virtual_registry_policy_subject

                upstream = ::VirtualRegistries::Packages::Maven::Upstream.new(
                  declared_params(include_missing: false).merge(group: group, name: 'test')
                )

                render_validation_error!(upstream) if upstream.invalid?

                status :ok
                upstream.test
              end
            end
          end

          namespace 'virtual_registries/packages/maven' do
            route_setting :lifecycle, :experiment

            namespace :registries do
              route_param :id, type: Integer, desc: 'The ID of the maven virtual registry' do
                namespace :upstreams do
                  desc 'List all maven virtual registry upstreams for a registry' do
                    detail 'This feature was introduced in GitLab 17.4. \
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
                  route_setting :authorization, permissions: :read_maven_virtual_registry_upstream,
                    boundary: -> { registry.group }, boundary_type: :group
                  get do
                    authorize! :read_virtual_registry, registry

                    upstreams = UPSTREAM_CLASSES.values
                      .flat_map { |klass| klass.eager_load_registry_upstream(registry:) }
                      # eager_load_registry_upstream filters registry_upstreams to this
                      # registry, so each upstream has exactly one; first is that row.
                      .sort_by { |u| u.registry_upstreams.first.position }

                    present upstreams,
                      with: Entities::VirtualRegistries::Packages::Maven::Upstream,
                      with_registry_upstream: true, exclude_upstream_id: true
                  end

                  desc 'Add a maven virtual registry upstream' do
                    detail 'This feature was introduced in GitLab 17.4. \
                        This feature behind the `maven_virtual_registry` feature flag.'
                    success code: 201, model: ::API::Entities::VirtualRegistries::Packages::Maven::Upstream
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
                    requires :url, type: String, desc: 'The URL of the maven virtual registry upstream',
                      allow_blank: false
                    requires :name, type: String, desc: 'The name of the maven virtual registry upstream',
                      allow_blank: false
                    optional :description, type: String, desc: 'The description of the maven virtual registry upstream'
                    optional :username, type: String, desc: 'The username of the maven virtual registry upstream'
                    optional :password, type: String, desc: 'The password of the maven virtual registry upstream'
                    optional :cache_validity_hours, type: Integer, values: 0..,
                      desc: 'The cache validity in hours. Defaults to 24, except for Maven Central upstreams, ' \
                        'which are forced to 0.'
                    optional :metadata_cache_validity_hours, type: Integer, default: 24, values: 1..,
                      desc: 'The metadata cache validity period in hours.'
                    all_or_none_of :username, :password
                  end
                  route_setting :authorization, permissions: :create_maven_virtual_registry_upstream,
                    boundary: -> { registry.group }, boundary_type: :group
                  post do
                    authorize! :create_virtual_registry, registry

                    new_upstream = registry.upstreams.create(
                      declared_params(include_missing: false).merge(group: registry.group)
                    )

                    render_validation_error!(new_upstream) unless new_upstream.persisted?

                    present new_upstream, with: Entities::VirtualRegistries::Packages::Maven::Upstream,
                      with_registry_upstream: true, exclude_upstream_id: true
                  end
                end

                namespace 'local/upstreams' do
                  desc 'Add a maven virtual registry local upstream' do
                    detail 'This feature was introduced in GitLab 19.2. \
                        This feature behind the `maven_virtual_registry` feature flag.'
                    success code: 201, model: ::API::Entities::VirtualRegistries::Packages::Maven::Upstream
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
                    requires :name, type: String, desc: 'The name of the maven virtual registry local upstream',
                      allow_blank: false
                    optional :description, type: String,
                      desc: 'The description of the maven virtual registry local upstream'
                    optional :local_group_id, type: Integer,
                      desc: 'The ID of the group targeted by the local upstream'
                    optional :local_project_id, type: Integer,
                      desc: 'The ID of the project targeted by the local upstream'
                    optional :cache_validity_hours, type: Integer, default: 24, values: 0..,
                      desc: 'The cache validity in hours.'
                    optional :metadata_cache_validity_hours, type: Integer, default: 1, values: 1..,
                      desc: 'The metadata cache validity period in hours.'
                    exactly_one_of :local_group_id, :local_project_id
                  end
                  route_setting :authorization, permissions: :create_maven_virtual_registry_upstream,
                    boundary: -> { registry.group }, boundary_type: :group
                  post do
                    authorize! :create_virtual_registry, registry

                    result = ::VirtualRegistries::Packages::Maven::Local::Upstreams::CreateService.new(
                      registry: registry,
                      current_user: current_user,
                      params: declared_params(include_missing: false)
                    ).execute

                    if result.error?
                      case result.reason
                      when :unauthorized
                        forbidden!(result.message)
                      when :invalid
                        render_validation_error!(result.payload)
                      else
                        bad_request!(result.message)
                      end
                    end

                    present result.payload, with: Entities::VirtualRegistries::Packages::Maven::Upstream,
                      with_registry_upstream: true, exclude_upstream_id: true
                  end
                end
              end
            end

            namespace :upstreams do
              route_param :id, type: Integer, desc: 'The ID of the maven virtual registry upstream' do
                desc 'Get a specific maven virtual registry upstream' do
                  detail 'This feature was introduced in GitLab 17.4. \
                        This feature behind the `maven_virtual_registry` feature flag.'
                  success ::API::Entities::VirtualRegistries::Packages::Maven::Upstream
                  failure [
                    { code: 400, message: 'Bad Request' },
                    { code: 401, message: 'Unauthorized' },
                    { code: 403, message: 'Forbidden' },
                    { code: 404, message: 'Not found' }
                  ]
                  tags %w[virtual_registries]
                  hidden true
                end
                route_setting :authorization, permissions: :read_maven_virtual_registry_upstream,
                  boundary: -> { upstream.group }, boundary_type: :group
                get do
                  present_maven_upstream(upstream)
                end

                desc 'Update a maven virtual registry upstream' do
                  detail 'This feature was introduced in GitLab 17.4. \
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
                  optional :name, type: String, desc: 'The name of the maven virtual registry upstream',
                    allow_blank: false
                  optional :description, type: String, desc: 'The description of the maven virtual registry upstream'
                  optional :url, type: String, desc: 'The URL of the maven virtual registry upstream',
                    allow_blank: false
                  optional :username, type: String, desc: 'The username of the maven virtual registry upstream'
                  optional :password, type: String, desc: 'The password of the maven virtual registry upstream'
                  optional :cache_validity_hours, type: Integer, desc: 'The validity of the cache in hours'
                  optional :metadata_cache_validity_hours, type: Integer,
                    desc: 'The metadata cache validity period in hours.'

                  at_least_one_of :name, :description, :url, :username, :password, :cache_validity_hours,
                    :metadata_cache_validity_hours
                end
                route_setting :authorization, permissions: :update_maven_virtual_registry_upstream,
                  boundary: -> { upstream.group }, boundary_type: :group
                patch do
                  authorize! :update_virtual_registry, upstream

                  render_validation_error!(upstream) unless upstream.update(declared_params(include_missing: false))

                  status :ok
                end

                desc 'Delete a maven virtual registry upstream' do
                  detail 'This feature was introduced in GitLab 17.4. \
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
                route_setting :authorization, permissions: :delete_maven_virtual_registry_upstream,
                  boundary: -> { upstream.group }, boundary_type: :group
                delete do
                  destroy_maven_upstream(upstream)
                end

                desc 'Purge cache for a maven virtual registry upstream' do
                  detail 'This feature was introduced in GitLab 18.2. \
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
                route_setting :authorization, permissions: :purge_maven_virtual_registry_upstream_cache,
                  boundary: -> { upstream.group }, boundary_type: :group
                delete :cache do
                  authorize! :destroy_virtual_registry, upstream

                  destroy_conditionally!(upstream) { upstream.purge_cache! }
                end

                desc 'Test connection to an existing maven virtual registry upstream' do
                  detail 'This feature was introduced in GitLab 18.3. \
                        This feature is behind the `maven_virtual_registry` feature flag.'
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
                route_setting :authorization, permissions: :test_maven_virtual_registry_upstream,
                  boundary: -> { upstream.group }, boundary_type: :group
                get :test do
                  authorize! :update_virtual_registry, upstream

                  upstream.test
                end

                desc 'Test connection to an existing Maven virtual registry upstream with optional override params' do
                  detail 'This feature was introduced in GitLab 18.7. \
                        This feature is behind the `maven_virtual_registry` feature flag.'
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
                  optional :url, type: String, desc: 'The URL of the Maven virtual registry upstream',
                    allow_blank: false
                  optional :username, type: String, desc: 'The username of the Maven virtual registry upstream'
                  optional :password, type: String, desc: 'The password of the Maven virtual registry upstream'
                end
                route_setting :authorization, permissions: :test_maven_virtual_registry_upstream,
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
                                    ::VirtualRegistries::Packages::Maven::Upstream.new(**upstream_params)
                                  else
                                    upstream
                                  end

                  render_validation_error!(test_upstream) if test_upstream != upstream && test_upstream.invalid?

                  status :ok
                  test_upstream.test
                end
              end
            end

            namespace 'local/upstreams' do
              route_param :id, type: Integer, desc: 'The ID of the maven virtual registry local upstream' do
                desc 'Get a specific maven virtual registry local upstream' do
                  detail 'This feature was introduced in GitLab 19.2. \
                        This feature behind the `maven_virtual_registry` feature flag.'
                  success ::API::Entities::VirtualRegistries::Packages::Maven::Upstream
                  failure [
                    { code: 400, message: 'Bad Request' },
                    { code: 401, message: 'Unauthorized' },
                    { code: 403, message: 'Forbidden' },
                    { code: 404, message: 'Not found' }
                  ]
                  tags %w[virtual_registries]
                  hidden true
                end
                route_setting :authorization, permissions: :read_maven_virtual_registry_upstream,
                  boundary: -> { local_upstream.group }, boundary_type: :group
                get do
                  present_maven_upstream(local_upstream)
                end

                desc 'Update a maven virtual registry local upstream' do
                  detail 'This feature was introduced in GitLab 19.2. \
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
                  optional :name, type: String,
                    desc: 'The name of the maven virtual registry local upstream', allow_blank: false
                  optional :description, type: String,
                    desc: 'The description of the maven virtual registry local upstream'
                  optional :cache_validity_hours, type: Integer, desc: 'The validity of the cache in hours'
                  optional :metadata_cache_validity_hours, type: Integer,
                    desc: 'The metadata cache validity period in hours.'

                  at_least_one_of :name, :description, :cache_validity_hours, :metadata_cache_validity_hours
                end
                route_setting :authorization, permissions: :update_maven_virtual_registry_upstream,
                  boundary: -> { local_upstream.group }, boundary_type: :group
                patch do
                  authorize! :update_virtual_registry, local_upstream

                  result = ::VirtualRegistries::Packages::Maven::Local::Upstreams::UpdateService.new(
                    upstream: local_upstream,
                    current_user: current_user,
                    params: declared_params(include_missing: false)
                  ).execute

                  render_validation_error!(result.payload) if result.error?

                  status :ok
                end

                desc 'Delete a maven virtual registry local upstream' do
                  detail 'This feature was introduced in GitLab 19.2. \
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
                route_setting :authorization, permissions: :delete_maven_virtual_registry_upstream,
                  boundary: -> { local_upstream.group }, boundary_type: :group
                delete do
                  destroy_maven_upstream(local_upstream)
                end
              end
            end
          end
        end
      end
    end
  end
end
