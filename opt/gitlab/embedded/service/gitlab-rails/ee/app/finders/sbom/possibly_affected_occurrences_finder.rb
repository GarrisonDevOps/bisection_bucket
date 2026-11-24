# frozen_string_literal: true

module Sbom
  class PossiblyAffectedOccurrencesFinder
    include Gitlab::Utils::StrongMemoize

    BATCH_SIZE = 100

    # Initializes the finder.
    #
    # @param purl_type [string] PURL type of the component to search for
    # @param package_name [string] Package name of the component to search for
    def initialize(purl_type:, package_name:)
      @purl_type = purl_type
      @package_name = package_name
    end

    def execute_in_batches(of: BATCH_SIZE)
      return unless search_scope

      search_scope.each_batch(of: of) do |batch|
        yield batch
          .unarchived
          .with_component_source_version_and_project
          .with_project_setting
          .with_project_security_setting
          .with_pipeline_project_and_namespace
          .with_occurrence_refs_for_advisory_scan
          .filter_by_non_nil_component_version
      end
    end

    private

    attr_reader :package_name, :purl_type

    def container_scanning?
      Enums::Sbom.container_scanning_purl_type?(purl_type)
    end

    def package_identity
      scope = if container_scanning?
                Sbom::SourcePackage.all
              else
                Sbom::Component.libraries
              end

      scope
        .by_purl_type_and_name(purl_type, normalized_name(purl_type, package_name))
        .select(:id)
        .first
    end
    strong_memoize_attr :package_identity

    def search_scope
      return unless package_identity

      case package_identity
      when Sbom::Component
        Sbom::Occurrence.filter_by_components(package_identity)
      when Sbom::SourcePackage
        Sbom::Occurrence.filter_by_source_packages(package_identity)
      end
    end
    strong_memoize_attr :search_scope

    # This can be removed after `UpdatePackageNameInPmAffectedPackages` has been completed.
    # See: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/183732
    def normalized_name(purl_type, package_name)
      ::Sbom::PackageUrl::Normalizer.new(type: purl_type, text: package_name).normalize_name
    end
  end
end
