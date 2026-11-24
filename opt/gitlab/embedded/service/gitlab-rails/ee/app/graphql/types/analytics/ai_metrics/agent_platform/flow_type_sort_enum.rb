# frozen_string_literal: true

module Types
  module Analytics
    module AiMetrics
      module AgentPlatform
        class FlowTypeSortEnum < BaseEnum
          graphql_name 'FlowTypeSort'
          description 'Values for Duo Agent Platform flow type sorting'

          value 'SESSIONS_COUNT_ASC', 'Sort by sessions count in ascending order.', value: :sessions_count_asc
          value 'SESSIONS_COUNT_DESC', 'Sort by sessions count in descending order.', value: :sessions_count_desc
          value 'USERS_COUNT_ASC', 'Sort by unique users count in ascending order.', value: :users_count_asc
          value 'USERS_COUNT_DESC', 'Sort by unique users count in descending order.', value: :users_count_desc
          value 'MEDIAN_TIME_ASC', 'Sort by median execution time in ascending order.', value: :median_time_asc
          value 'MEDIAN_TIME_DESC', 'Sort by median execution time in descending order.', value: :median_time_desc
        end
      end
    end
  end
end
