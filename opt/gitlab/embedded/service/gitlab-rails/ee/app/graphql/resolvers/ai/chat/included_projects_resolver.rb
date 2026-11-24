# frozen_string_literal: true

# This GraphQL query is used in Duo Chat's `/include <repository>` command
#
# This returns the projects relevant to the user, in the following order of relevance:
#   - recently contributed: projects the user contributed to within the last month (excluding public forked projects)
#   - recently visited: projects the user visited within the last month (excluding public forked projects)
#   - authorized only: projects that the user can see if logged in (excluding all public projects)
# ...up to a maximum results size of MAX_RESULTS_COUNT
#
# If the `search` parameter is given:
#   - the projects' path and name are filtered by the `search` term;
#     the project description is not included in the filter
#   - each of the list of projects by relevance category (recently contributed, recently visited, authorized only)
#     are ordered by `search` term similarity score
#
# If the `search` parameter is not given:
#   - there is no filter on the projects' path and name
#   - each of the list of projects by relevance category (recently contributed, recently visited, authorized only)
#     are ordered by recency according to the relevance category
module Resolvers
  module Ai
    module Chat
      class IncludedProjectsResolver < BaseResolver
        # Return only the 10 most relevant projects
        MAX_RESULTS_COUNT = 10

        AI_CHAT_FEATURE = :ai_chat

        type Types::ProjectType.connection_type, null: true

        argument :search, GraphQL::Types::String,
          required: false,
          description: 'Search query, which can be for the project name or path. Minimum 3 characters.'

        def resolve(**args)
          params = finder_params(args)

          records = []
          records_count = 0

          relevance_categories = [:recently_contributed, :recently_visited, :authorized_only]
          relevance_categories.each do |category|
            finder = build_finder(category, params: params, found_count: records_count)

            records = (records + finder.execute.all).uniq(&:id)
            records_count = records.length

            return records if records_count >= MAX_RESULTS_COUNT
          end

          records
        end

        private

        def finder_params(args)
          {
            search: args[:search],
            namespace_ai_feature: AI_CHAT_FEATURE
          }
        end

        def build_finder(category, params:, found_count:)
          limit = MAX_RESULTS_COUNT - found_count

          case category
          when :recently_contributed
            ::Users::RelevantProjectsFinder.new(
              current_user,
              params: params.merge(
                relevance_category: :recently_contributed, include_public: true, limit: limit
              )
            )
          when :recently_visited
            ::Users::RelevantProjectsFinder.new(
              current_user,
              params: params.merge(
                relevance_category: :recently_visited, include_public: true, limit: limit
              )
            )
          when :authorized_only
            ::Users::RelevantProjectsFinder.new(
              current_user, params: params.merge(limit: limit)
            )
          end
        end
      end
    end
  end
end
