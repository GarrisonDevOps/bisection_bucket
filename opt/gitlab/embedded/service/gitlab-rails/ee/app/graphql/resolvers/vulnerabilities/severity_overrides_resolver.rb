# frozen_string_literal: true

module Resolvers
  module Vulnerabilities
    class SeverityOverridesResolver < VulnerabilitiesBaseResolver
      type ::Types::Vulnerabilities::SeverityOverrideType, null: true

      def resolve(**_args)
        Gitlab::Graphql::Loaders::Vulnerabilities::SeverityOverrideLoader.new(context, object)
      end
    end
  end
end
