# frozen_string_literal: true

module Vulnerabilities
  class BulkEsOperationService
    def initialize(relation)
      @relation = relation
    end

    def execute
      unless ::Search::Elastic::VulnerabilityIndexHelper.indexing_allowed?
        yield relation if block_given?

        return true
      end

      all_records = preload(relation)
      eligible = all_records.select(&:maintaining_elasticsearch?)

      yield relation if block_given?

      ::Elastic::ProcessBookkeepingService.track!(*eligible.map(&:es_tracking_target))
    end

    private

    attr_reader :relation

    def preload(relation)
      vulnerabilities = relation.dup
      vulnerabilities.load

      # Project preload for Vulnerability#elastic_reference method
      # Project.Namespace preload for Vulnerabilities::Read.generate_es_parent method,
      # which is in turn called in Vulnerability#elastic_reference method.
      associations = if vulnerabilities.first.is_a?(Vulnerability)
                       [project: [:namespace]]
                     elsif vulnerabilities.first.is_a?(Vulnerabilities::Read)
                       [vulnerability: [project: [:namespace]]]
                     end

      ActiveRecord::Associations::Preloader.new(
        records: vulnerabilities,
        associations: associations
      ).call

      if vulnerabilities.first.is_a?(Vulnerability)
        ActiveRecord::Associations::Preloader.new(
          records: vulnerabilities,
          associations: [:vulnerability_read]
        ).call

        vulnerabilities.each { |v| v.vulnerability_read&.association(:project)&.target = v.project }
      end

      preloaded_namespaces = vulnerabilities.map { |r| r.project.namespace }
      ::Namespaces::Preloaders::NamespaceRootAncestorPreloader.new(preloaded_namespaces).execute

      vulnerabilities
    end
  end
end
