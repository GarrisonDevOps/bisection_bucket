# frozen_string_literal: true

module WorkItems
  module Statuses
    module Lifecycles
      # Shared status lifecycle interface for work item type classes.
      #
      # A plain module (not a concern) mixed into both SystemDefined::Type and
      # Custom::Type so the resolution methods live in one place. Both classes
      # respond to #persistable_id and #system_defined_lifecycle, which is all
      # the Provider needs to resolve a lifecycle.
      #
      # All methods expect a root namespace id.
      module HasLifecycle
        def status_lifecycle_for(namespace_id)
          Provider.new(namespace_id).find_by_type(self)
        end

        def custom_lifecycle_for(namespace_id)
          Provider.new(namespace_id).find_custom_by_type(self)
        end

        def custom_status_enabled_for?(namespace_id)
          return false unless namespace_id

          ::WorkItems::TypeCustomLifecycle
            .with_namespace_id(namespace_id)
            .exists?(work_item_type_id: persistable_id)
        end
      end
    end
  end
end
