# frozen_string_literal: true

module Types
  module Vulnerabilities
    # rubocop: disable Graphql/AuthorizeTypes -- object is a hash.
    class CvssType < BaseObject
      graphql_name 'CvssType'
      description "Represents a vulnerability's CVSS score."

      authorize_granular_token skip_reason: :parent_authorizes

      include ::Gitlab::Utils::StrongMemoize

      field :vector, ::GraphQL::Types::String,
        null: false, description: 'CVSS vector string.', hash_key: "vector"

      field :vendor, ::GraphQL::Types::String,
        null: false, description: 'Vendor who assigned the CVSS score.', hash_key: "vendor"

      field :version, ::GraphQL::Types::Float,
        null: false, description: 'Version of the CVSS.'

      field :base_score, ::GraphQL::Types::Float,
        null: false, description: 'Base score of the CVSS.'

      field :overall_score, ::GraphQL::Types::Float,
        null: false, description: 'Overall score of the CVSS.'

      field :severity, ::Types::Vulnerabilities::CvssSeverityEnum,
        null: false, description: 'Severity calculated from the overall score.'

      delegate :overall_score, :severity, :version, to: :cvss

      def base_score
        if cvss.respond_to?(:base_score)
          cvss.base_score
        else
          cvss.overall_score
        end
      end

      private

      def cvss
        ::CvssSuite.new(object['vector'])
      end
      strong_memoize_attr :cvss
    end
  end
  # rubocop: enable Graphql/AuthorizeTypes
end
