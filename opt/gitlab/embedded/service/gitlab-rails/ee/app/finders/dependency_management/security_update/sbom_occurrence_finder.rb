# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    # Resolves the SBOM occurrence to remediate for a single vulnerability.
    #
    # A vulnerability can link to several SBOM occurrences (same advisory across
    # lock files or package managers). This narrows them to the supported ones,
    # ordered by id so the caller can take `.first` deterministically and have
    # repeated triggers target the same branch.
    class SbomOccurrenceFinder
      def initialize(project:, vulnerability:)
        @project = project
        @vulnerability = vulnerability
      end

      # @return [ActiveRecord::Relation] supported occurrences for the
      #   vulnerability, ordered by id. Empty when none use a supported package
      #   manager. Callers take `.first` to get the occurrence to remediate.
      def execute
        vulnerability.sbom_occurrences
          .for_project(project)
          .filter_by_package_managers(Eligibility::SUPPORTED_PACKAGE_MANAGERS)
          .with_component_version
          .order_by_id
      end

      private

      attr_reader :project, :vulnerability
    end
  end
end
