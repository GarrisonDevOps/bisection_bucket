# frozen_string_literal: true

module Resolvers
  module Security
    class AnalyzerGroupStatusResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include Gitlab::Utils::StrongMemoize

      type Types::Security::AnalyzerGroupStatusType, null: true

      authorize :read_security_inventory

      description 'Resolves analyzer status information for a group.'

      def resolve(**args)
        ::Security::AnalyzerGroupStatusFinder
          .new(object, args)
          .execute
      end
    end
  end
end
