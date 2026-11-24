# frozen_string_literal: true

module Resolvers
  module Analytics
    module AiUsage
      class UsageEventsResolver < BaseResolver
        type ::Types::Analytics::AiUsage::AiUsageEventType.connection_type, null: true

        argument :start_date, Types::DateType,
          required: false,
          description: 'Start date for the date range. Default is 7 days before the current date.'

        argument :end_date, Types::DateType,
          required: false,
          description: 'End date for the date range. Default is the current day.'

        argument :events, [Types::Analytics::AiUsage::AiUsageEventTypeEnum],
          required: false,
          description: 'Filters by events.'

        argument :user_ids, [::Types::GlobalIDType[::User]],
          required: false,
          description: 'Filters by users.'

        def ready?(**args)
          validate_params!(args)

          super
        end

        def resolve(**args)
          params = params_with_defaults(args)

          ::Ai::UsageEventsFinder.new(current_user,
            namespace: namespace,
            from: params[:start_date],
            to: params[:end_date],
            events: params[:events],
            users: params[:user_ids]&.map(&:model_id)
          ).execute
        end

        private

        def validate_params!(args)
          params = params_with_defaults(args)

          return if params[:start_date] > params[:end_date] - 1.month

          raise Gitlab::Graphql::Errors::ArgumentError, 'maximum date range is 1 month'
        end

        def namespace
          case object
          when Namespace then object
          when Project then object.project_namespace
          end
        end

        def params_with_defaults(args)
          { start_date: 7.days.ago.beginning_of_day, end_date: Time.current.end_of_day }.merge(args)
        end
      end
    end
  end
end
