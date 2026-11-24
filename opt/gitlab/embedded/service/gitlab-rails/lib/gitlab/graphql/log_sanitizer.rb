# frozen_string_literal: true

module Gitlab
  module Graphql
    # Redacts a query's variables and document before either reaches graphql_json.log.
    module LogSanitizer
      def self.variables(variables, operation_name)
        filtered = ActiveSupport::ParameterFilter
          .new(::Gitlab::Graphql::QueryAnalyzers::AST::LoggerAnalyzer::FILTER_PARAMETERS)
          .filter(variables)

        ::Gitlab::Graphql::VariableFilters::Registry.filter(filtered, operation_name)&.to_s
      end

      def self.query_string(query)
        # query.document is already parsed and memoized by graphql-ruby
        return query.query_string unless contains_mutation?(query.document)

        query.sanitized_query_string
      end

      # A document can contain several operations and is logged whole, so check
      # every operation, not just the selected one.
      def self.contains_mutation?(document)
        return true if document.nil? # ensures unparseable queries are also redacted

        document.definitions.any? do |definition|
          definition.is_a?(GraphQL::Language::Nodes::OperationDefinition) && definition.operation_type == 'mutation'
        end
      end
      private_class_method :contains_mutation?
    end
  end
end
