# frozen_string_literal: true

module Sbom
  class ComponentVersionsFinder
    def initialize(object, component_name)
      @object = object
      @component_name = component_name
    end

    def execute
      base_relation
        .select_distinct(on: "version")
        .order_by_version
    end

    private

    attr_reader :object, :component_name

    def base_relation
      case object
      when Project
        project_relation
      when Group
        group_relation
      else
        raise ArgumentError, "can't find components for #{object.class.name}"
      end
    end

    def project_relation
      Sbom::ComponentVersion
        .by_project(object)
        .by_component_name(component_name)
    end

    def group_relation
      Sbom::ComponentVersion
        .by_component_id(group_occurrences.select(:component_id))
    end

    def group_occurrences
      Sbom::Occurrence
        .for_namespace_and_descendants(object)
        .by_component_name_collated(component_name)
    end
  end
end
