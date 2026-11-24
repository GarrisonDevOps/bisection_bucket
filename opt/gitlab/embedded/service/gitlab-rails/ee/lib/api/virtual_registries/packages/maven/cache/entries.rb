# frozen_string_literal: true

module API
  module VirtualRegistries
    module Packages
      module Maven
        module Cache
          class Entries < ::API::Base
            include ::API::Concerns::VirtualRegistries::Packages::Maven::SharedSetup
            include ::API::Concerns::VirtualRegistries::SharedAuthentication
            include ::API::PaginationParams

            helpers do
              include ::Gitlab::Utils::StrongMemoize

              def target_group
                request.path.include?('/upstreams') ? upstream.group : cache_entry.group
              end

              def upstream
                ::VirtualRegistries::Packages::Maven::Upstream.find(params[:id])
              end
              strong_memoize_attr :upstream

              def cache_entries
                upstream
                  .default_cache_entries
                  .order_iid_desc
                  .search_by_relative_path(params[:search])
              end

              def cache_entry
                ::VirtualRegistries::Packages::Maven::Cache::Remote::Entry
                  .default
                  .find_by_group_id_and_iid!(*declared_params[:id].split)
              end
              strong_memoize_attr :cache_entry
            end

            namespace 'virtual_registries/packages/maven' do
              route_setting :lifecycle, :experiment

              namespace :upstreams do
                route_param :id, type: Integer, desc: 'The ID of the maven virtual registry upstream' do
                  namespace :cache_entries do
                    desc 'List maven virtual registry upstream cache entries' do
                      detail 'This feature was introduced in GitLab 17.4. \
                            This feature is behind the `maven_virtual_registry` feature flag.'
                      success ::API::Entities::VirtualRegistries::Packages::Maven::Cache::Remote::Entry
                      failure [
                        { code: 400, message: 'Bad Request' },
                        { code: 401, message: 'Unauthorized' },
                        { code: 403, message: 'Forbidden' },
                        { code: 404, message: 'Not found' }
                      ]
                      tags %w[virtual_registries]
                      is_array true
                      hidden true
                    end

                    params do
                      optional :search, type: String, desc: 'Search query', documentation: { example: 'foo/bar/mypkg' }
                      use :pagination
                    end
                    route_setting :authorization, permissions: :read_maven_virtual_registry_upstream_cache_entry,
                      boundary: -> { upstream.group }, boundary_type: :group
                    get do
                      authorize! :read_virtual_registry, upstream

                      present paginate(cache_entries),
                        with: ::API::Entities::VirtualRegistries::Packages::Maven::Cache::Remote::Entry
                    end
                  end
                end
              end

              namespace :cache_entries do
                desc 'Delete a maven virtual registry upstream cache entry' do
                  detail 'This feature was introduced in GitLab 17.4. \
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
                params do
                  requires :id, type: String, coerce_with: Base64.method(:urlsafe_decode64),
                    desc: 'The base64 encoded cache entry identifier (format: "group_id iid")',
                    documentation: { example: 'MTIzNCA1Njc4' }
                end
                route_setting :authorization, permissions: :delete_maven_virtual_registry_upstream_cache_entry,
                  boundary: -> { cache_entry.upstream.group }, boundary_type: :group
                delete '*id' do
                  authorize! :destroy_virtual_registry, cache_entry.upstream

                  destroy_conditionally!(cache_entry) do |cache_entry|
                    render_validation_error!(cache_entry) unless cache_entry.pending_destruction!
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
