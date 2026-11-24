# frozen_string_literal: true

module Security
  # Finds the IDs of projects within a namespace by their assigned security attributes.
  #
  # Example: "Show me projects that are tagged 'Production' AND 'Critical',
  #           but NOT tagged 'Deprecated'."
  #
  # Accepts an array of attribute_filters, each with:
  #   - operator: 'is_one_of' (include) or 'is_not_one_of' (exclude)
  #   - attributes: array of security attribute IDs
  #
  # Multiple 'is_one_of' filters are combined with AND (project must match all groups).
  # Multiple 'is_not_one_of' filters are merged and applied as a single exclusion.
  class ProjectsByAttributesFinder
    IS_ONE_OF = 'is_one_of'
    IS_NOT_ONE_OF = 'is_not_one_of'

    def initialize(namespace:, attribute_filters: [])
      @namespace = namespace
      @attribute_filters = attribute_filters || []
    end

    def execute
      return [] if namespace.nil?
      return [] if attribute_filters.blank?

      is_one_of_filters, is_not_one_of_filters = partition_filters_by_operator
      return [] if is_one_of_filters.empty? && is_not_one_of_filters.empty?

      resolve_project_ids(is_one_of_filters, is_not_one_of_filters)
    end

    private

    attr_reader :namespace, :attribute_filters

    def project_attributes_in_namespace
      Security::ProjectToSecurityAttribute.within(namespace.traversal_ids)
    end

    def validated_security_attribute_ids(attributes)
      attributes.filter_map do |attr|
        Integer(attr, exception: false)
      end
    end

    def partition_filters_by_operator
      is_one_of = []
      is_not_one_of = []

      attribute_filters.each do |filter|
        security_attribute_ids = validated_security_attribute_ids(filter[:attributes])
        next if security_attribute_ids.empty?

        case filter[:operator].to_s
        when IS_ONE_OF     then is_one_of << security_attribute_ids
        when IS_NOT_ONE_OF then is_not_one_of << security_attribute_ids
        end
      end

      [is_one_of, is_not_one_of]
    end

    # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- Building filter subqueries on sec DB; results are already scoped to a namespace
    def resolve_project_ids(is_one_of_filters, is_not_one_of_filters)
      project_attributes_in_namespace
        .by_security_attributes(is_one_of_filters, is_not_one_of_filters)
        .distinct
        .pluck(:project_id)
    end
    # rubocop:enable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit
  end
end
