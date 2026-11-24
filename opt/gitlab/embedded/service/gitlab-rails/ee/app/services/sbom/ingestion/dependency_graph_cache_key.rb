# frozen_string_literal: true

module Sbom
  module Ingestion
    class DependencyGraphCacheKey
      attr_reader :project, :sbom_report

      def initialize(project, sbom_report)
        @project = project
        @sbom_report = sbom_report
      end

      def key
        return @cache_key if defined?(@cache_key)

        components = sbom_report.components
          .sort_by(&:ref)
          .map(&:ref)
          .join

        @cache_key ||= "dependency-graph_#{project.id}_#{OpenSSL::Digest::SHA256.hexdigest(components)}"
      end
    end
  end
end
