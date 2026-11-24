# frozen_string_literal: true

module WorkItems
  module DataSync
    module Widgets
      class CustomFields < Base
        def after_save_commit
          return unless target_work_item.get_widget(:custom_fields)

          ::WorkItems::Widgets::CopyCustomFieldValuesService.new(work_item: work_item,
            target_work_item: target_work_item).execute
        end
      end
    end
  end
end
