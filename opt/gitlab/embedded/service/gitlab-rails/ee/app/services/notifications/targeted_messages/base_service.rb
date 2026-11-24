# frozen_string_literal: true

module Notifications
  module TargetedMessages
    class BaseService
      FOUND_INVALID_NAMESPACES = :found_invalid_namespaces

      def initialize(params)
        @params = params.dup
      end

      private

      attr_reader :params, :targeted_message, :parsed_namespaces

      def parse_namespaces
        csv = params.delete(:namespace_ids_csv)

        @parsed_namespaces = Notifications::TargetedMessages::NamespaceIdsBuilder.new(csv).build
      end

      def handle_failure
        @targeted_message.errors.add(:base, parsed_namespaces[:message]) if add_csv_error?

        failure
      end

      def add_csv_error?
        parsed_namespaces[:success] == false
      end

      def partial_success?
        parsed_namespaces[:invalid_namespace_ids].any?
      end

      def success
        ServiceResponse.success(payload: targeted_message)
      end

      def failure
        ServiceResponse.error(
          message: 'Failed to complete the service',
          payload: targeted_message
        )
      end
    end
  end
end
