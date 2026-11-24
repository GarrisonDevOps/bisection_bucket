# frozen_string_literal: true

module Vulnerabilities
  module Remediations
    class BatchDestroyService
      include BaseServiceUtility

      def initialize(remediations:)
        @remediations = remediations
      end

      def execute
        return success_response if remediations.blank?
        raise argument_error unless remediations.is_a?(ActiveRecord::Relation)

        remediations
          .tap { |remediations| Upload.destroy_for_associations!(remediations) }
          .then(&:delete_all)
          .then { |deleted_count| success_response(deleted_count) }
      end

      private

      attr_reader :remediations

      def argument_error
        ArgumentError.new('remediations must be of type ActiveRecord::Relation')
      end

      def success_response(deleted_count = 0)
        ServiceResponse.success(payload: { rows_deleted: deleted_count })
      end
    end
  end
end
