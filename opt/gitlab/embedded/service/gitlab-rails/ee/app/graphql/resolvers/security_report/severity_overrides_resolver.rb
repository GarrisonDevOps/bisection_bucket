# frozen_string_literal: true

module Resolvers
  module SecurityReport # rubocop:disable Gitlab/BoundedContexts -- this follows the same format as the rest of the directory
    class SeverityOverridesResolver < VulnerabilitiesBaseResolver
      type ::Types::Vulnerabilities::SeverityOverrideType, null: true

      def resolve(**_args)
        return unless object.vulnerability

        Gitlab::Graphql::Loaders::Vulnerabilities::SeverityOverrideLoader.new(context, object.vulnerability)
      end
    end
  end
end
