# frozen_string_literal: true

module Resolvers
  module Security
    class EnabledPartialScansResolver < EnabledScansResolver # rubocop:disable Graphql/ResolverType -- Defined on parent
      def model
        ::Vulnerabilities::PartialScan
      end
    end
  end
end
