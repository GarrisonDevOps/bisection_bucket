# frozen_string_literal: true

module Resolvers
  module Projects
    module Analytics
      module ValueStreamDashboard
        class CountResolver < BaseResolver
          include Resolvers::Analytics::ValueStreamDashboard::CommonCountResolverMethods

          type ::Types::Analytics::ValueStreamDashboard::CountType, null: true

          authorize :read_project_level_value_stream_dashboard_overview_counts

          argument :identifier, Types::Analytics::ValueStreamDashboard::ProjectMetricEnum,
            required: true,
            description: 'Type of counts to retrieve.'

          private

          def namespace
            object.project_namespace
          end
        end
      end
    end
  end
end
