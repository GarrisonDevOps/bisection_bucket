# frozen_string_literal: true

module Resolvers
  module Analytics
    module ContributionAnalytics
      class ContributionsResolver < BaseResolver
        type Types::Analytics::ContributionAnalytics::ContributionMetadataType, null: true

        NUMBER_OF_DAYS = ::Gitlab::ContributionAnalytics::DataCollector::MAX_RANGE_DAYS
        MAX_RANGE = NUMBER_OF_DAYS.days.freeze

        argument :from, GraphQL::Types::ISO8601Date, required: true,
          description: 'Start date of the reporting time range.'
        argument :to, GraphQL::Types::ISO8601Date, required: true,
          description: 'End date of the reporting time range. ' \
          "The end date must be within #{NUMBER_OF_DAYS} days after the start date."
        max_page_size 500
        default_page_size 500

        def resolve(from:, to:, after: nil, first: nil)
          validate_date_range!(from, to)

          data_collector = Gitlab::ContributionAnalytics::DataCollector.new(group: object, from: from, to: to)
          users = data_collector.users(**pagination_arguments(after, first))

          result = users.map do |user|
            { user: user }.tap do |counts_per_user|
              Gitlab::ContributionAnalytics::DataCollector::EVENT_TYPES.each do |event_type|
                counts_per_user[event_type] = data_collector.totals[event_type].fetch(user.id, 0)
              end
            end
          end

          if result.any?
            start_cursor = encode(result.first[:user].id)
            end_cursor = encode(result.last[:user].id)
          end

          Gitlab::Graphql::ExternallyPaginatedArray.new(start_cursor, end_cursor, *result)
        end

        private

        def encode(value)
          Base64.strict_encode64(value.to_s) if value
        end

        def decode(value)
          Base64.strict_decode64(value) if value
        end

        def pagination_arguments(after, first)
          {}.tap do |hash|
            hash[:limit] = first || self.class.default_page_size
            decoded_value = decode(after)
            hash[:after_id] = Integer(decoded_value) if decoded_value.present?
          end.compact
        end

        def validate_date_range!(from, to)
          if (to - from).days > MAX_RANGE
            error_message = format(
              s_('ContributionAnalytics|The given date range is larger than %{number_of_days} days'),
              number_of_days: NUMBER_OF_DAYS)
            raise ::Gitlab::Graphql::Errors::ArgumentError, error_message
          end

          return unless to < from

          error_message = s_('ContributionAnalytics|The to date is earlier than the given from date')
          raise ::Gitlab::Graphql::Errors::ArgumentError, error_message
        end
      end
    end
  end
end
