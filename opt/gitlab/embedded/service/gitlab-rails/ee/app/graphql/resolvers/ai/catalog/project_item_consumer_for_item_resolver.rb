# frozen_string_literal: true

module Resolvers
  module Ai
    module Catalog
      class ProjectItemConsumerForItemResolver < BaseResolver
        description 'AI Catalog item configuration for the given item in a project.'

        type ::Types::Ai::Catalog::ItemConsumerType, null: true

        argument :id,
          ::Types::GlobalIDType[::Ai::Catalog::Item],
          required: true,
          description: 'Global ID of the catalog item to return the configuration of.'

        argument :include_inherited,
          GraphQL::Types::Boolean,
          required: false,
          default_value: true,
          description: "Include a configuration inherited from the project's top-level group, when the project " \
            'has no configuration of its own. Defaults to `true`. Has no effect when the ' \
            '`ai_catalog_group_inherited_consumers` feature flag is disabled.'

        def resolve(id:, include_inherited:)
          context.scoped_set!(:ai_catalog_authorizing_project, object)

          BatchLoader::GraphQL.for([object, id.model_id.to_i])
            .batch(key: include_inherited) do |project_item_pairs, loader, args|
            root_ancestors_by_id = preload_root_ancestors(project_item_pairs.map(&:first).uniq)

            project_consumers, inherited_consumers = load_consumers(
              project_item_pairs, root_ancestors_by_id, include_inherited: args[:key]
            )
            preload_max_access_in_groups(inherited_consumers.values.map(&:group).uniq)

            project_item_pairs.each do |project, item_id|
              consumer = project_consumers[[project.id, item_id]]
              consumer ||= inherited_consumers[[project.root_ancestor.id, item_id]]
              next unless consumer

              consumer.project = project if consumer.project_id

              loader.call([project, item_id], consumer)
            end
          end
        end

        private

        def load_consumers(project_item_pairs, root_ancestors_by_id, include_inherited:)
          project_pairs = project_item_pairs.map { |project, item_id| [project.id, item_id] }
          group_pairs = include_inherited ? root_group_item_pairs(project_item_pairs) : []

          consumers = ::Ai::Catalog::ItemConsumer.for_container_item_pairs(:project, project_pairs)
          if group_pairs.any?
            consumers = consumers.or(
              ::Ai::Catalog::ItemConsumer.inheritance.for_container_item_pairs(:group, group_pairs)
            )
          end

          consumers = consumers.with_items.to_a
          inherited_consumers = consumers.select(&:inheritance?)

          inherited_consumers.each { |consumer| consumer.group = root_ancestors_by_id[consumer.group_id] }

          [
            consumers.select(&:project_id).index_by { |consumer| [consumer.project_id, consumer.ai_catalog_item_id] },
            inherited_consumers.index_by { |consumer| [consumer.group_id, consumer.ai_catalog_item_id] }
          ]
        end

        def root_group_item_pairs(project_item_pairs)
          project_item_pairs.filter_map do |project, item_id|
            root_ancestor = project.root_ancestor
            next unless root_ancestor.is_a?(::Group)
            next unless ::Feature.enabled?(:ai_catalog_group_inherited_consumers, root_ancestor)

            [root_ancestor.id, item_id]
          end.uniq
        end

        def preload_max_access_in_groups(groups)
          return if groups.empty?

          ::Preloaders::UserMaxAccessLevelInGroupsPreloader.new(groups, current_user).execute
        end

        def preload_root_ancestors(projects)
          namespaces = projects.map(&:namespace)
          root_ancestors = ::Namespace.id_in(namespaces.map { |namespace| namespace.traversal_ids.first }.uniq).to_a

          ActiveRecord::Associations::Preloader.new(
            records: root_ancestors,
            associations: [:namespace_settings, :ai_settings, :organization]
          ).call

          ActiveRecord::Associations::Preloader.new(
            records: root_ancestors.grep(::Group),
            associations: :saml_provider
          ).call

          root_ancestors_by_id = root_ancestors.index_by(&:id)
          namespaces.each { |namespace| namespace.root_ancestor = root_ancestors_by_id[namespace.traversal_ids.first] }

          root_ancestors_by_id
        end
      end
    end
  end
end
