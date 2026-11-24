# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    class VulnerableSbomOccurrencesFinder
      include Gitlab::Utils::StrongMemoize

      # After testing this with various batch sizes on large
      # projects like gitlab.com/gitlab-org/gitlab we determined
      # that this was an optimal batch size to iterate through
      # occurrences with.
      BATCH_SIZE = 100

      # Initializes the finder for fetching SBOM component occurrences paired with vulnerability occurrences
      #
      # @param project [Project] The project to search within
      def initialize(project:, package_manager:, severity_level:)
        @project = project
        @package_manager = package_manager
        @severity_level = severity_level
      end

      # Executes the finder in batches and returns SBOM occurrences ordered by the
      # severity of their _associated_ vulnerabilities. Vulnerabilities themselves are
      # not returned, or preloaded.
      #
      # The query returns pairs of SBOM component occurrences filtered to only include:
      #
      # - Package manager specified
      # - Severity level specified
      # - Detected (non-dismissed) vulnerabilities
      # - Unarchived projects and occurrences
      #
      # Results are ordered by ascending id order
      #
      # @return [ActiveRecord::Relation] Relation of Sbom::Occurrence with active vulnerabilities
      # @return [Nil] If project is archived
      def execute_in_batches
        return if project.archived?

        scope.distinct_each_batch(of: BATCH_SIZE, column: :id) do |batch|
          # `distinct_each_batch` uses `unscoped` internally, which strips relation
          # metadata like `preload`. We reapply it here on the concrete batch so
          # that traversing vulnerabilities and findings does not cause N+1 queries.
          ids = batch.pluck_primary_key
          yield Sbom::Occurrence.with_vulnerabilities_and_findings.id_in(ids)
        end
      end

      private

      attr_reader :project, :package_manager, :severity_level

      def scope
        Sbom::Occurrence
          .for_project(project)
          .filter_by_package_managers(package_manager)
          .filter_by_highest_severity(severity_level)
          .with_active_vulnerabilities
          .with_component_version
      end
    end
  end
end
