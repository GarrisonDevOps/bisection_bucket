# frozen_string_literal: true

module EE
  module WorkItems
    module DataSync
      module BaseCreateService
        extend ::Gitlab::Utils::Override

        override :initialize_callbacks!
        def initialize_callbacks!(work_item)
          super

          return callbacks if callbacks.any?(::WorkItems::DataSync::Widgets::Status)

          base_type = work_item.work_item_type.base_type
          root_namespace = work_item.resource_parent.root_ancestor
          write_rows = ::WorkItems::Statuses::FeatureFlags.write_rows_without_license?(base_type, root_namespace)
          return callbacks unless write_rows

          callbacks << ::WorkItems::DataSync::Widgets::Status.new(
            work_item: original_work_item,
            target_work_item: work_item,
            current_user: current_user,
            params: { operation: operation }
          )
        end
      end
    end
  end
end
