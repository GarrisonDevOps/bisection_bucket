# frozen_string_literal: true

module WorkItems
  module LegacyEpics
    class CreateService
      include ErrorMapping

      def initialize(group:, perform_spam_check: true, current_user: nil, params: {})
        @group = group
        @current_user = current_user
        # Convert to Hash because params may be an instance of ActionController::Params
        @params = params.to_hash.symbolize_keys!
        @perform_spam_check = perform_spam_check
      end

      def execute_without_rate_limiting
        execute(without_rate_limiting: true)
      end

      def execute(without_rate_limiting: false)
        execute_method = without_rate_limiting ? :execute_without_rate_limiting : :execute
        service_result = create_service.try(execute_method)

        transform_result(service_result)
      end

      private

      def create_service
        transformed_params, widget_params =
          ::Gitlab::WorkItems::LegacyEpics::WidgetParamsExtractor.new(params).extract

        ::WorkItems::CreateService.new(
          container: group,
          perform_spam_check: perform_spam_check,
          current_user: current_user,
          params: transformed_params,
          widget_params: widget_params
        )
      end

      def transform_result(result)
        # The legacy service Epics::CreateService returns an epic record instead of a service response
        # so in case of failing to create the work item we create a new epic that includes the service errors

        if result.try(:error?)
          new_epic = Epic.new

          new_epic.errors.add(:base,
            result[:message].include?(
              WORK_ITEM_NOT_FOUND_ERROR
            ) ? EPIC_NOT_FOUND_ERROR : result[:message])
          return new_epic
        end

        result.payload[:work_item]&.reload&.synced_epic
      end

      attr_reader :group, :current_user, :params, :perform_spam_check
    end
  end
end
