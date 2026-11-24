# frozen_string_literal: true

module Security
  module Attributes
    # This service deletes project-to-attribute associations for soft-deleted security attributes.
    #
    # Responsibility:
    # - Delete project-to-attribute associations (project_to_security_attributes table) in batches
    #
    # Why batched deletion?
    # - Avoids relying on database CASCADE behavior which can be slow for large datasets
    # - Provides better performance when there are many project associations (BATCH_SIZE = 100)
    # - Gives explicit control over the deletion process and error handling
    #
    # Note: Hard deletion of attributes and categories is handled by the worker that calls this service.
    # This keeps the service focused on a single responsibility: cleaning up associations.
    class ProjectToSecurityAttributeDestroyService < BaseService
      BATCH_SIZE = 100
      def initialize(attribute_ids:)
        @attribute_ids = Array(attribute_ids)
      end

      def execute
        total_deleted = delete_projects_to_security_attribute

        ServiceResponse.success(
          message: "Successfully deleted project to security attribute associations",
          payload: { deleted_count: total_deleted }
        )
      rescue StandardError => e
        ServiceResponse.error(
          message: "Failed to delete project to security attribute associations: #{e.message}"
        )
      end

      private

      attr_reader :attribute_ids

      def delete_projects_to_security_attribute
        total_deleted = 0

        attribute_ids.each do |attribute_id|
          deleted_count = delete_associations_for_attribute(attribute_id)
          total_deleted += deleted_count
        end
        total_deleted
      end

      def delete_associations_for_attribute(attribute_id)
        total_deleted = 0

        loop do
          deleted = Security::ProjectToSecurityAttribute.by_attribute_id(attribute_id).limit(BATCH_SIZE).delete_all
          total_deleted += deleted
          break if deleted < BATCH_SIZE
        end

        total_deleted
      end
    end
  end
end
