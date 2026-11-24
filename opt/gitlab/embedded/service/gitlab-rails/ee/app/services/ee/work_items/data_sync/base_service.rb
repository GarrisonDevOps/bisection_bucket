# frozen_string_literal: true

module EE
  module WorkItems
    module DataSync
      module BaseService
        extend ::Gitlab::Utils::Override

        override :skip_target_work_item_type_resolution_for_epic?
        def skip_target_work_item_type_resolution_for_epic?
          work_item.work_item_type&.epic?
        end
      end
    end
  end
end
