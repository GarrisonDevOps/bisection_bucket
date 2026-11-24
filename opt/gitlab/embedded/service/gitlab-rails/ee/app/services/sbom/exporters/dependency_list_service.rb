# frozen_string_literal: true

module Sbom
  module Exporters
    class DependencyListService
      include WriteBlob

      attr_reader :export, :relation

      def initialize(export, relation)
        @export = export
        @relation = relation
      end

      def generate(&block)
        write_json_blob(blob, &block)
      end

      private

      delegate :project, :author, to: :export

      def blob
        DependencyListEntity.represent(sbom_occurrences, serializer_parameters)
      end

      def sbom_occurrences
        # rubocop:disable CodeReuse/ActiveRecord -- Preloading logic is coupled with DependencyListEntity
        relation.preload(*preloads)
        # rubocop:enable CodeReuse/ActiveRecord
      end

      def preloads
        [
          :component,
          :component_version,
          :vulnerabilities
        ]
      end

      def serializer_parameters
        {
          request: EntityRequest.new({
            project: project,
            user: author,
            license_override_applicator: license_override_applicator
          }),
          pipeline: pipeline,
          project: project,
          include_vulnerabilities: true,
          license_override_applicator: license_override_applicator
        }
      end

      def license_override_applicator
        @license_override_applicator ||= ::Security::LicenseOverrideApplicator.new(project)
      end

      def pipeline
        project.latest_ingested_sbom_pipeline
      end
    end
  end
end
