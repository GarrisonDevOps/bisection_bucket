# frozen_string_literal: true

module WorkItems
  module EpicAsWorkItem
    extend ActiveSupport::Concern

    included do
      include Gitlab::Utils::StrongMemoize
      include ::WorkItems::UnifiedAssociations::Notes
      include ::WorkItems::UnifiedAssociations::ResourceLabelEvents
      include ::WorkItems::UnifiedAssociations::ResourceStateEvents
      include ::WorkItems::UnifiedAssociations::DescriptionVersions
      include ::WorkItems::UnifiedAssociations::Subscriptions
      include ::WorkItems::UnifiedAssociations::Events

      # this overrides the scope in Issuable by removing the labels association from it as labels are now preloaded
      # by loading labels from the work item
      scope :includes_for_bulk_update, -> do
        association_symbols = %i[author sync_object assignees epic group metrics project source_project target_project]
        associations = association_symbols.select do |assoc|
          reflect_on_association(assoc)
        end

        includes(*associations)
      end

      def container
        case resource_parent
        when Group
          resource_parent
        when Project
          resource_parent.group
        end
      end
      strong_memoize_attr :container

      def unified_associations?
        try(:sync_object)
      end

      def batched_object
        [
          [id, self.class.base_class.name],
          [sync_object&.id, sync_object&.class&.base_class&.name]
        ]
      end
      strong_memoize_attr :batched_object
    end
  end
end
