# frozen_string_literal: true

module Resolvers
  module Ai
    module Catalog
      class ItemVersionsResolver < BaseResolver
        # TODO: Extend to all items visible to the current_user https://gitlab.com/gitlab-org/gitlab/-/issues/584822
        description 'Public AI Catalog item versions.'

        type ::Types::Ai::Catalog::VersionInterface.connection_type, null: false

        argument :created_after, Types::TimeType,
          required: false,
          description: 'Item versions created after the timestamp.'

        argument :exclude_deprecated, GraphQL::Types::Boolean,
          required: false,
          default_value: true,
          description: 'Whether to exclude deprecated versions from the results. Defaults to true.'

        def resolve(**args)
          ::Ai::Catalog::ItemVersionsFinder.new(
            current_user,
            params: finder_params(args)
          ).execute
        end

        private

        def finder_params(args)
          args.merge(organization: current_organization)
        end
      end
    end
  end
end
