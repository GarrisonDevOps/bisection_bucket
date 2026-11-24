# frozen_string_literal: true

module WorkItems
  module DataSync
    module Widgets
      class HealthStatus < Base
        def before_create
          return unless target_work_item.get_widget(:health_status)
          return unless target_work_item.namespace.licensed_feature_available?(:issuable_health_status)

          target_work_item.health_status = work_item.health_status
        end

        def post_move_cleanup
          # nothing to do, health_status is a field work_item record, it will be removed upon the work_item deletion
        end
      end
    end
  end
end
