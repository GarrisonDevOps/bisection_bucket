# frozen_string_literal: true

module Analytics
  module AiAnalytics
    class AiMetricsService
      attr_reader :current_user, :namespace, :from, :to, :fields

      def initialize(current_user, namespace:, from:, to:, fields:)
        @current_user = current_user
        @namespace = namespace
        @from = from
        @to = to
        @fields = fields
      end

      def execute
        data = add_usage({}, CodeSuggestionUsageService, DuoChatUsageService, DuoUsageService,
          TroubleshootUsageService)

        ServiceResponse.success(payload: data)
      end

      private

      def add_usage(data, *service_classes)
        service_classes.each do |klass|
          usage = klass.new(
            current_user,
            namespace: namespace,
            from: from,
            to: to,
            fields: fields
          ).execute

          data.merge!(usage.payload) if usage.success?
        end

        data
      end
    end
  end
end
