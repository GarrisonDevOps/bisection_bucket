# frozen_string_literal: true

module Security
  module Attributes
    class BulkUpdateService < BaseService
      def initialize(group_ids:, project_ids:, attribute_ids:, mode:, current_user:)
        @group_ids = group_ids
        @project_ids = project_ids
        @attribute_ids = attribute_ids
        @mode = mode
        @current_user = current_user
      end

      def execute
        Security::Attributes::BulkUpdateSchedulerWorker.perform_async(
          group_ids,
          project_ids,
          attribute_ids,
          mode.to_s,
          current_user.id
        )

        ServiceResponse.success(message: "Bulk update operation initiated")
      end

      private

      attr_reader :group_ids, :project_ids, :attribute_ids, :mode, :current_user
    end
  end
end
