# frozen_string_literal: true

module API
  module Admin
    module Search
      class Migrations < ::API::Base
        feature_category :global_search
        urgency :low

        helpers do
          def ensure_elasticsearch_indexing_enabled!
            bad_request!('indexing is not enabled') unless ::Gitlab::CurrentSettings.elasticsearch_indexing?
          end
        end

        before do
          authenticated_as_admin!
          ensure_elasticsearch_indexing_enabled!
        end

        namespace 'admin' do
          resources 'search/migrations' do
            desc 'List all advanced search migrations' do
              detail 'Lists all advanced search migrations for the GitLab instance.'
              failure [
                { code: 401, message: '401 Unauthorized' },
                { code: 403, message: '403 Forbidden' },
                { code: 404, message: '404 Not found' }
              ]
              tags %w[search]
            end
            route_setting :tier, :premium
            route_setting :authorization, permissions: :read_search_migration, boundary_type: :instance,
              assignable_when: [:admin]
            get do
              migrations = Elastic::DataMigrationService.migrations

              present(migrations, with: ::API::Entities::Search::Migration)
            end
          end

          params do
            requires :migration_id,
              types: [Integer, String],
              desc: 'Version or name of the search migration.'
          end
          resources 'search/migrations/:migration_id' do
            desc 'Retrieve an advanced search migration' do
              detail 'Retrieves a specified advanced search migration by migration version or name.'
              success ::API::Entities::Search::Migration
              failure [
                { code: 401, message: '401 Unauthorized' },
                { code: 403, message: '403 Forbidden' },
                { code: 404, message: '404 Not found' }
              ]
              tags %w[search]
            end
            params do
              requires :migration_id,
                types: [Integer, String],
                desc: 'Version or name of the search migration.'
            end
            route_setting :tier, :premium
            route_setting :authorization, permissions: :read_search_migration, boundary_type: :instance,
              assignable_when: [:admin]
            get do
              name_or_version = params[:migration_id]
              migration = if name_or_version.is_a?(Numeric)
                            Elastic::DataMigrationService[name_or_version]
                          else
                            Elastic::DataMigrationService.find_by_name(name_or_version)
                          end

              not_found!('migration not found') if migration.nil?

              present(migration, with: ::API::Entities::Search::Migration)
            end
          end
        end
      end
    end
  end
end
