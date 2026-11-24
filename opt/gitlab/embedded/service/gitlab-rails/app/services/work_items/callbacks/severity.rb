# frozen_string_literal: true

module WorkItems
  module Callbacks
    class Severity < Base
      def before_create
        assign_severity
      end

      def before_update
        assign_severity
      end

      private

      def assign_severity
        return unless params.key?(:severity)
        return unless has_permission?(:admin_work_item)
        return if params[:severity] == work_item.severity

        work_item.assign_attributes(issuable_severity_attributes: { severity: params[:severity] })
      end
    end
  end
end
