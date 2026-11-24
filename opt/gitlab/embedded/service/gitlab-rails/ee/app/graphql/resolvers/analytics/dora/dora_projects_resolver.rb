# frozen_string_literal: true

module Resolvers
  module Analytics
    module Dora
      class DoraProjectsResolver < NamespaceProjectsResolver
        extend ::Gitlab::Utils::Override

        argument :start_date, Types::DateType,
          required: true,
          description: 'Date range to start DORA lookup from.'

        argument :end_date, Types::DateType,
          required: true,
          description: 'Date range to end DORA lookup at.'

        type Types::ProjectType, null: true

        MAX_RANGE = Gitlab::Analytics::CycleAnalytics::RequestParams::MAX_RANGE_DAYS # same range as in VSA

        def ready?(**args)
          return super if (args[:end_date] - args[:start_date]).days <= MAX_RANGE

          raise Gitlab::Graphql::Errors::ArgumentError, "maximum date range is #{MAX_RANGE.in_days.to_i} days."
        end

        private

        override :find_projects
        def find_projects(args)
          super.with_existing_dora_records(args[:start_date], args[:end_date])
        end
      end
    end
  end
end
