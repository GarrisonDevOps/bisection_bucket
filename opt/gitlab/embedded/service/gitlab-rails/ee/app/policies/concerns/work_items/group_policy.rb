# frozen_string_literal: true

module WorkItems
  module GroupPolicy
    extend ActiveSupport::Concern

    included do
      rule { ~is_root_namespace }.policy do
        prevent :create_work_item_type
        prevent :update_work_item_type
        prevent :admin_work_item_lifecycle
        prevent :update_work_item_setting
      end

      rule { ~configurable_work_item_types_enabled }.policy do
        prevent :create_work_item_type
        prevent :update_work_item_type
      end

      rule { ~work_item_statuses_available }.policy do
        prevent :admin_work_item_lifecycle
      end
    end
  end
end
