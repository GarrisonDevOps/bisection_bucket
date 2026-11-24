# frozen_string_literal: true

module Resolvers
  class PipelineSecurityReportFindingsResolver < BaseResolver
    type ::Types::PipelineSecurityReportFindingType, null: true

    alias_method :pipeline, :object

    argument :report_type, [GraphQL::Types::String],
      required: false,
      description: 'Filter vulnerability findings by report type.'

    argument :severity, [GraphQL::Types::String],
      required: false,
      description: 'Filter vulnerability findings by severity ' \
        "(#{::Security::Finding.severities.keys.map { |s| "`#{s}`" }.join(', ')}). " \
        'An unknown severity returns an error.'

    argument :scanner, [GraphQL::Types::String],
      required: false,
      description: 'Filter vulnerability findings by Scanner.externalId.'

    argument :state, [Types::VulnerabilityStateEnum],
      required: false,
      description: 'Filter vulnerability findings by state.'

    argument :sort, Types::Security::PipelineSecurityReportFindingSortEnum,
      required: false,
      default_value: 'severity_desc',
      description: 'List vulnerability findings by sort order.'

    def resolve(**args)
      # The finder raises KeyError on a severity it does not know. Refuse it
      # here, naming the value.
      validate_filter_values!('severity', args[:severity], ::Security::Finding.severities.keys)

      params = args.merge(
        limit: limit(args),
        cursor: ::Gitlab::Pagination::Keyset::GraphqlCursorBuilder.build(after: args[:after], before: args[:before])
      )

      ::Security::FindingsFinder.new(pipeline, params: params)
        .execute
    end

    private

    def validate_filter_values!(argument_name, values, valid_values)
      invalid_values = (Array(values).map(&:to_s) - valid_values).uniq
      return if invalid_values.empty?

      raise Gitlab::Graphql::Errors::ArgumentError,
        "Argument '#{argument_name}' has an invalid value (#{invalid_values.map(&:to_json).join(', ')}). " \
          "Valid values are: #{valid_values.join(', ')}."
    end

    def limit(args)
      args[:first] || args[:last] || context.schema.default_max_page_size
    end
  end
end
