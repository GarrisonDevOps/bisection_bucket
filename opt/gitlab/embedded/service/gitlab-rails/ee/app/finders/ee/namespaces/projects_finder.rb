# frozen_string_literal: true

module EE
  # Namespaces::ProjectsFinder
  #
  # Extends Namespaces::ProjectsFinder
  #
  # Added arguments:
  #   params:
  #     has_vulnerabilities: boolean
  #     has_code_coverage: boolean
  #     sbom_component_id: integer
  #
  module Namespaces
    module ProjectsFinder
      extend ::Gitlab::Utils::Override

      private

      override :filter_projects
      def filter_projects(collection)
        collection = super(collection)
        collection = with_vulnerabilities(collection)
        collection = with_code_coverage(collection)
        collection = with_compliance_framework(collection)
        collection = by_negated_compliance_framework_filters(collection)
        collection = with_sbom_component_version(collection)
        by_compliance_framework_presence(collection)
      end

      def with_compliance_framework(collection)
        filter_id = params.dig(:compliance_framework_filters, :id)
        filter_ids = params.dig(:compliance_framework_filters, :ids) || []

        filter_ids << filter_id unless filter_id.nil?

        return collection if filter_ids.blank?

        filter_ids.each do |framework_id|
          collection = collection.with_compliance_frameworks(framework_id)
        end

        collection
      end

      def by_negated_compliance_framework_filters(collection)
        filter_id = params.dig(:compliance_framework_filters, :not, :id)
        filter_ids = params.dig(:compliance_framework_filters, :not, :ids) || []

        filter_ids << filter_id unless filter_id.nil?

        return collection if filter_ids.blank?

        collection.not_with_compliance_frameworks(filter_ids)
      end

      def by_compliance_framework_presence(collection)
        filter = params.dig(:compliance_framework_filters, :presence_filter)
        return collection if filter.nil?

        case filter.to_sym
        when :any
          collection.any_compliance_framework
        when :none
          collection.missing_compliance_framework
        else
          raise ArgumentError, "The presence filter is not supported: '#{filter}'"
        end
      end

      override :sort
      def sort(items)
        if params[:sort] == :excess_repo_storage_size_desc
          return items.order_by_excess_repo_storage_size_desc(namespace.actual_size_limit)
        end

        super(items)
      end

      def with_vulnerabilities(items)
        return items unless params[:has_vulnerabilities].present?

        items.has_vulnerabilities
      end

      def with_code_coverage(items)
        return items unless params[:has_code_coverage].present?

        items.with_coverage_feature_usage(default_branch: true)
      end

      def with_sbom_component_version(items)
        return items unless params[:sbom_component_id].present?

        project_ids_with_component = Sbom::Occurrence
          .for_namespace_and_descendants(namespace)
          .filter_by_component_version_ids(params[:sbom_component_id])
          .select('DISTINCT ON (project_id) project_id')
          .map(&:project_id)

        items.id_in(project_ids_with_component)
      end
    end
  end
end
