# frozen_string_literal: true

module Sbom
  class ComponentsFinder
    COMPONENT_NAMES_LIMIT = 30

    def initialize(namespace, query)
      @namespace = namespace
      @query = query.to_s
    end

    def execute
      base_relation
        .select(distinct(on: Arel.sql(Sbom::Occurrence::COMPONENT_NAME_WITH_C_COLLATION)))
        .merge(Sbom::Occurrence.order_by_component_name_collated)
        .limit(COMPONENT_NAMES_LIMIT)
    end

    private

    attr_reader :namespace, :query

    def base_relation
      case namespace
      when Project
        project_relation
      when Group
        group_relation
      else
        raise ArgumentError, "can't find components for #{namespace.class.name}"
      end
    end

    def distinct(on:)
      select_values = Sbom::Component.column_names.map do |column|
        Sbom::Component.adapter_class.quote_table_name("#{Sbom::Component.table_name}.#{column}")
      end

      distinct_sql = Arel::Nodes::DistinctOn.new([on]).to_sql

      "#{distinct_sql} #{select_values.join(', ')}"
    end

    def project_relation
      Sbom::Component
        .for_project(namespace)
        .merge(Sbom::Occurrence.by_component_name_substring(query))
    end

    def group_relation
      Sbom::Component
        .joins(:occurrences) # rubocop:disable CodeReuse/ActiveRecord -- context-specific
        .merge(Sbom::Occurrence.by_component_name_prefix(query))
        .merge(Sbom::Occurrence.for_namespace_and_descendants(namespace))
    end
  end
end
