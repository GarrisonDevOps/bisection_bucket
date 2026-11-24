# frozen_string_literal: true

module Resolvers
  module Security
    class SecurityPolicyEligibleProjectsResolver < BaseResolver
      include ::Security::ProjectIdParsing

      MAX_FILTER_IDS = 100

      type Types::ProjectType.connection_type, null: true

      argument :search, GraphQL::Types::String,
        required: false,
        description: 'Search query for project name or path.'

      argument :ids, [::Types::GlobalIDType[::Project]],
        required: false,
        validates: { length: { maximum: MAX_FILTER_IDS } },
        description: 'Filter eligible projects by global IDs (used to hydrate already-selected projects). ' \
          "A maximum of #{MAX_FILTER_IDS} IDs can be provided."

      def resolve(**args)
        args[:ids] = parse_project_ids(args[:ids]) if args[:ids].present?

        ::Security::SecurityPolicyEligibleProjectsFinder
          .new(current_user, object, args)
          .execute
      end
    end
  end
end
