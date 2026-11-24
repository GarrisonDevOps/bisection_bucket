# frozen_string_literal: true

module Types
  module Vulnerabilities
    class RepresentationInformationType < BaseObject
      graphql_name 'VulnerabilityRepresentationInformation'
      description 'Represents vulnerability information'

      authorize :read_vulnerability_representation_information

      field :resolved_in_commit_sha, GraphQL::Types::String, null: true,
        description: 'SHA of the commit where the vulnerability was resolved.'

      def resolved_in_commit_sha
        # Do not expose commit SHA for redacted secrets to prevent exposure of refs containing the secret
        return if redact_resolved_secret?

        object.resolved_in_commit_sha
      end

      private

      def redact_resolved_secret?
        object.vulnerability&.secret_detection? &&
          object.removed_from_code?
      end
    end
  end
end
