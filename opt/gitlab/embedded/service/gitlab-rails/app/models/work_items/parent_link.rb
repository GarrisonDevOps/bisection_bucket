# frozen_string_literal: true

module WorkItems
  class ParentLink < ApplicationRecord
    include RelativePositioning

    self.table_name = 'work_item_parent_links'

    MAX_CHILDREN = 5000

    belongs_to :work_item
    belongs_to :work_item_parent, class_name: 'WorkItem'
    belongs_to :namespace

    validates :work_item_parent, presence: true
    validates :work_item, presence: true, uniqueness: true
    validates_with Organizations::SameOrganizationValidator, left: :work_item_parent, right: :work_item
    validate :validate_hierarchy_restrictions
    validate :validate_cyclic_reference
    validate :validate_max_children
    validate :validate_confidentiality
    validate :check_existing_related_link, on: :create

    scope :for_parents, ->(parent_ids) { where(work_item_parent_id: parent_ids) }
    scope :for_children, ->(children_ids) { where(work_item: children_ids) }

    class << self
      def parent_ids_with_children(parent_ids)
        for_parents(parent_ids).distinct.pluck(:work_item_parent_id) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by the given parent ids
      end

      # Returns { parent_id => { [work_item_type_id, state_id] => count } } for all descendants, in one query.
      def descendant_counts_by_type_and_state(parent_ids)
        links = arel_table
        issues = WorkItem.arel_table
        # UNION ALL skips the costly dedup (each item has one parent). The path guards against corrupt cycles.
        cte = Gitlab::SQL::RecursiveCTE.new(:descendant_links, union_args: { remove_duplicates: false })

        cte << for_parents(parent_ids).select(
          links[:work_item_parent_id].as('root_id'),
          links[:work_item_id],
          'ARRAY[work_item_parent_links.work_item_parent_id, work_item_parent_links.work_item_id] AS tree_path',
          'work_item_parent_links.work_item_id = work_item_parent_links.work_item_parent_id AS tree_cycle'
        )
        cte << unscoped
          .select(
            cte.table[:root_id],
            links[:work_item_id],
            'descendant_links.tree_path || work_item_parent_links.work_item_id',
            'work_item_parent_links.work_item_id = ANY(descendant_links.tree_path)'
          )
          .from([links, cte.table])
          .where(links[:work_item_parent_id].eq(cte.table[:work_item_id]))
          .where(cte.table[:tree_cycle].eq(false))

        counts = WorkItem
          .with.recursive(cte.to_arel)
          .joins(issues.join(cte.table).on(cte.table[:work_item_id].eq(issues[:id])).join_sources)
          .where(cte.table[:tree_cycle].eq(false))
          .group(Arel.sql('descendant_links.root_id'), issues[:work_item_type_id], issues[:state_id])
          .count

        counts
          .group_by { |(root_id, _type_id, _state_id), _count| root_id }
          .transform_values { |rows| rows.to_h { |(_root_id, type_id, state_id), count| [[type_id, state_id], count] } }
      end

      def has_public_children?(parent_id)
        joins(:work_item).where(work_item_parent_id: parent_id, 'issues.confidential': false).exists?
      end

      def has_confidential_parent?(id)
        link = find_by_work_item_id(id)
        return false unless link

        link.work_item_parent.confidential?
      end

      def relative_positioning_query_base(parent_link)
        where(work_item_parent_id: parent_link.work_item_parent_id)
      end

      def relative_positioning_parent_column
        :work_item_parent_id
      end

      def for_work_item(work_item)
        find_or_initialize_by(work_item: work_item)
      end
    end

    private

    def validate_max_children
      return unless work_item_parent && work_item_parent_id_changed?

      max = persisted? ? MAX_CHILDREN : MAX_CHILDREN - 1
      return unless work_item_parent.child_links.count > max

      errors.add :work_item_parent, _('parent already has maximum number of children.')
    end

    def validate_confidentiality
      return unless work_item_parent && work_item

      return unless work_item_parent.confidential? && !work_item.confidential?

      errors.add :work_item, format(
        _("cannot assign a non-confidential %{work_item_type} to a confidential " \
          "parent. Make the %{work_item_type} confidential and try again."),
        work_item_type: work_item.work_item_type.name.downcase
      )
    end

    def validate_hierarchy_restrictions
      return unless work_item && work_item_parent

      restriction = ::WorkItems::TypesFramework::SystemDefined::HierarchyRestriction.find_by(
        parent_type_id: resolved_type_id_for(work_item_parent),
        child_type_id: resolved_type_id_for(work_item)
      )

      if restriction.nil?
        errors.add :work_item, _("it's not allowed to add this type of parent item")
        return
      end

      validate_depth(restriction.maximum_depth)
    end

    def validate_depth(depth)
      return unless depth
      return if resolved_type_id_for(work_item) != resolved_type_id_for(work_item_parent)

      return unless work_item_parent.same_type_base_and_ancestors.count + work_item.same_type_descendants_depth > depth

      errors.add :work_item, _('reached maximum depth')
    end

    def resolved_type_id_for(item)
      @resolved_type_ids ||= {}
      @resolved_type_ids[item.id] ||= item.work_item_type_id
    end

    def validate_cyclic_reference
      return unless work_item_parent&.id && work_item&.id

      errors.add :work_item, _('is not allowed to point to itself') if work_item.id == work_item_parent.id

      return unless work_item_parent.ancestors.any? { |ancestor| work_item.id == ancestor.id }

      errors.add :work_item, _("it's already present in this item's hierarchy")
    end

    def check_existing_related_link
      return unless work_item && work_item_parent

      existing_link = WorkItems::RelatedWorkItemLink.for_items(work_item, work_item_parent)
      return if existing_link.none?

      errors.add(:work_item, _('cannot assign a linked work item as a parent'))
    end
  end
end

WorkItems::ParentLink.prepend_mod
