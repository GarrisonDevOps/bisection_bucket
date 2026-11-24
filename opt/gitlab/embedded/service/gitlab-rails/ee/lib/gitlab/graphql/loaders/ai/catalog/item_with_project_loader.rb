# frozen_string_literal: true

module Gitlab
  module Graphql
    module Loaders
      module Ai
        module Catalog
          # Batches, for every catalog item on the page, the project and organization that
          # `Ai::Catalog::ItemPolicy` and `Types::ProjectType` read, so `project` and
          # `userPermissions` stop walking project -> namespace -> root ancestor per item.
          class ItemWithProjectLoader
            def initialize(item, current_user)
              @item = item
              @current_user = current_user
            end

            def find
              BatchLoader::GraphQL.for(item).batch(key: current_user) do |items, loader, args|
                preload(items, args[:key])

                items.each { |record| loader.call(record, record) }
              end
            end

            private

            attr_reader :item, :current_user

            def preload(items, user)
              ActiveRecord::Associations::Preloader.new(records: items, associations: :organization).call

              projects = ::Project.id_in(items.filter_map(&:project_id).uniq)
              ::Preloaders::ProjectPolicyPreloader.new(projects, user).execute
              ActiveRecord::Associations::Preloader.new(
                records: projects,
                associations: [:route, :project_setting, :project_namespace, { namespace: :route }]
              ).call

              projects_by_id = projects.index_by(&:id)
              items.each do |record|
                record.association(:project).target = projects_by_id[record.project_id]
              end
            end
          end
        end
      end
    end
  end
end
