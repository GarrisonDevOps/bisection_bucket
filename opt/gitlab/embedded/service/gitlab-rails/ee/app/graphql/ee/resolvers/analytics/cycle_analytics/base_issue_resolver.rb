# frozen_string_literal: true

module EE
  module Resolvers
    module Analytics
      module CycleAnalytics
        module BaseIssueResolver
          extend ActiveSupport::Concern

          prepended do
            argument :epic_id, ::GraphQL::Types::ID,
              required: false,
              description: 'ID of an epic associated with the issues.'

            argument :iteration_id, ::GraphQL::Types::ID,
              required: false,
              description: 'ID of an iteration associated with the issues.'

            argument :weight, GraphQL::Types::Int,
              required: false,
              description: 'Weight applied to the issue.'

            argument :my_reaction_emoji, GraphQL::Types::String,
              required: false,
              description: 'Filter by reaction emoji applied by the current user.'

            argument :not, ::Types::Analytics::CycleAnalytics::NegatedIssuableFilterInputType,
              required: false,
              description: 'Argument used for adding negated filters.'
          end
        end
      end
    end
  end
end
