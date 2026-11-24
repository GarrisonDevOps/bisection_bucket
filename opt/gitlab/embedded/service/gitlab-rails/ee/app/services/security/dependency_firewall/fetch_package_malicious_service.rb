# frozen_string_literal: true

module Security
  module DependencyFirewall
    class FetchPackageMaliciousService
      def initialize(name:, purl_type:, version:)
        @name = name
        @purl_type = purl_type
        @version = version
      end

      # Wraps each match as `{ advisory: ... }` (not a bare boolean) so the audit
      # event can report what flagged the package.
      def execute
        PackageMetadata::MalwareAdvisoriesFinder
          .new(name: name, purl_type: purl_type, version: version)
          .execute
          .map { |affected_package| { advisory: affected_package.malware_advisory } }
      end

      private

      attr_reader :name, :purl_type, :version
    end
  end
end
