# frozen_string_literal: true

module WorkItems
  module Callbacks
    class Weight < Base
      def after_initialize
        params[:weight] = nil if excluded_in_new_type?

        return unless params.present? && params.key?(:weight)
        return unless work_item.weight_available? && has_permission?(:admin_work_item)

        work_item.weight = params[:weight]
      end
    end
  end
end
