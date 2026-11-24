# frozen_string_literal: true

module EE
  module WorkItems
    module RelatedWorkItemLink
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize

      EPIC_ENTITY_WORK_ITEM_ASSOCIATIONS = [
        :dates_source, :labels, :color, :author, :sync_object,
        { namespace: [:saml_provider, :route], parent_link: { work_item_parent: :sync_object } }
      ].freeze
      BLOCKED_WORK_ITEM_BATCH_SIZE = 100

      class_methods do
        # Work items outside the namespace that block an open work item in it.
        # Blockers count only open work items, so closed ones are skipped.
        def blocking_ids_outside_namespace(namespace)
          ids = Set.new
          namespace.work_items.opened.each_batch(of: BLOCKED_WORK_ITEM_BATCH_SIZE, column: :iid) do |batch|
            ids += blocks
              .where(target_id: batch.select(:id))
              .joins(:source).where.not(source: { namespace_id: namespace.id })
              .limit(BLOCKED_WORK_ITEM_BATCH_SIZE * self::MAX_LINKS_COUNT)
              .pluck(:source_id)
          end

          ids.to_a
        end
      end

      prepended do
        include FromUnion

        has_one :related_epic_link, class_name: '::Epic::RelatedEpicLink', foreign_key: 'issue_link_id',
          inverse_of: :related_work_item_link

        scope :for_source_type, ->(type) { joins(:source).where(source: { work_item_type_id: type }) }
        scope :for_target_type, ->(type) { joins(:target).where(target: { work_item_type_id: type }) }

        scope :preload_for_epic_link, -> do
          preload(
            :related_epic_link,
            source: [
              :namespace,
              { synced_epic: [:sync_object, { group: [:saml_provider, :route] },
                { work_item: EPIC_ENTITY_WORK_ITEM_ASSOCIATIONS }] }
            ],
            target: [
              :namespace,
              { synced_epic: [:sync_object, { group: [:saml_provider, :route] },
                { work_item: EPIC_ENTITY_WORK_ITEM_ASSOCIATIONS }] }
            ]
          )
        end

        scope :for_work_item_type_in_namespaces, ->(namespace_ids_cte, type) do
          namespace_ids_subquery = namespace_ids_cte.table.project(namespace_ids_cte.table[:id])
          source_table = ::WorkItem.arel_table.alias('source')
          target_table = ::WorkItem.arel_table.alias('target')

          # Query 1: Links where source is in accessible namespaces
          source_in_namespace = with(namespace_ids_cte.to_arel)
            .for_source_type(type)
            .for_target_type(type)
            .where(source_table[:namespace_id].in(namespace_ids_subquery))

          # Query 2: Links where target is in accessible namespaces
          target_in_namespace = with(namespace_ids_cte.to_arel)
            .for_source_type(type)
            .for_target_type(type)
            .where(target_table[:namespace_id].in(namespace_ids_subquery))

          from_union([source_in_namespace, target_in_namespace], remove_duplicates: true)
        end
      end

      def synced_related_epic_link
        return unless source.synced_epic || target.synced_epic

        ::Epic::RelatedEpicLink.find_by(source: source.synced_epic, target: target.synced_epic)
      end
      strong_memoize_attr :synced_related_epic_link
    end
  end
end
