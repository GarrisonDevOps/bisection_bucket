# frozen_string_literal: true

module ComplianceManagement
  module Frameworks
    class ProjectSettingsDestroyService < BaseService
      def initialize(namespace_id:, framework_ids:)
        @namespace_id = namespace_id
        @framework_ids = Array(framework_ids)
      end

      def execute
        total_deleted = delete_project_settings

        ServiceResponse.success(
          message: "Destroyed related project settings for frameworks",
          payload: { deleted_count: total_deleted }
        )
      rescue StandardError => e
        ServiceResponse.error(
          message: "Failed to delete project settings for frameworks: #{e.message}"
        )
      end

      private

      def delete_project_settings
        if namespace_id.present?
          total_deleted = 0

          # rubocop: disable CodeReuse/ActiveRecord -- Using pluck here is safe, already batching with batch size 100
          ComplianceManagement::Framework
            .with_namespaces(namespace_id)
            .find_in_batches(batch_size: 100) do |batch|
              deleted_count = ComplianceManagement::ComplianceFramework::ProjectSettings
                .delete_by_framework(batch.pluck(:id)) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- see above

              total_deleted += deleted_count
            end
          # rubocop: enable CodeReuse/ActiveRecord

          total_deleted
        else
          ComplianceManagement::ComplianceFramework::ProjectSettings.delete_by_framework(framework_ids)
        end
      end

      attr_reader :framework_ids, :namespace_id
    end
  end
end
