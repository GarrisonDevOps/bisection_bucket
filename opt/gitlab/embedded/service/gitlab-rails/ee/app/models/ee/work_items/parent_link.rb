# frozen_string_literal: true

module EE
  module WorkItems
    module ParentLink
      extend ActiveSupport::Concern

      prepended do
        attr_accessor :work_item_syncing
        alias_method :work_item_syncing?, :work_item_syncing
        validate :validate_legacy_hierarchy, unless: :work_item_syncing?

        has_one :epic_issue, class_name: 'EpicIssue', foreign_key: 'work_item_parent_link_id',
          inverse_of: :work_item_parent_link

        has_one :epic, class_name: 'Epic', foreign_key: 'work_item_parent_link_id',
          inverse_of: :work_item_parent_link

        private

        def validate_legacy_hierarchy
          return unless work_item_parent&.work_item_type&.base_type == 'epic' && work_item&.has_epic?
          return if work_item.epic_issue.epic.issue_id == work_item_parent.id

          errors.add :work_item, _('already assigned to an epic')
        end

        def resolved_type_id_for(item)
          @resolved_type_ids ||= {}
          @resolved_type_ids[item.id] ||= begin
            type = item.work_item_type
            type.respond_to?(:delegation_source) ? type.delegation_source.id : item.work_item_type_id
          end
        end
      end
    end
  end
end
