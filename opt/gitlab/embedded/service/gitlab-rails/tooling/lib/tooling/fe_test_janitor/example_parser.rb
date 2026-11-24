# frozen_string_literal: true

require 'prism'

module Tooling
  module FeTestJanitor
    # Parses a single *_spec.rb file and extracts RSpec examples with their
    # source lines, so the classifier can run signal matching per example.
    #
    # Parsing strategy: Prism builds the syntax tree, so each example's body
    # ends at its real closing `end` or `}`, whatever keywords or strings it holds.
    # We detect `it`, `specify`, and `scenario` blocks, plus `it_behaves_like` and
    # `include_examples` calls, which are marked as shared and not analyzed.
    # Shared example definitions are skipped, because their calls are not analyzed.
    class ExampleParser
      ParseError = Class.new(StandardError)

      Example = Struct.new(:description, :line_number, :body, :shared, keyword_init: true)

      EXAMPLE_METHODS = %i[it specify scenario].freeze
      SHARED_EXAMPLE_METHODS = %i[it_behaves_like include_examples].freeze
      SHARED_DEFINITION_METHODS = %i[shared_examples shared_examples_for shared_context].freeze

      def initialize(source)
        @source = source
        @lines = source.lines
      end

      # Returns an Array of Example structs, in source order.
      # Raises ParseError when the source is not valid Ruby.
      def parse
        result = Prism.parse(@source)
        raise ParseError, parse_error_message(result) unless result.success?

        examples = []
        collect(result.value, examples)
        examples
      end

      private

      def parse_error_message(result)
        result.errors.map { |error| "line #{error.location.start_line}: #{error.message}" }.join('; ')
      end

      def collect(node, examples)
        return if shared_definition?(node)

        example = build_example(node)
        examples << example if example

        # An example's own body holds no further examples, but a shared example
        # call can take a block of contexts and examples.
        return if example && !example.shared

        node.compact_child_nodes.each { |child| collect(child, examples) }
      end

      def shared_definition?(node)
        node.is_a?(Prism::CallNode) && node.receiver.nil? && SHARED_DEFINITION_METHODS.include?(node.name)
      end

      def build_example(node)
        return unless node.is_a?(Prism::CallNode) && node.receiver.nil?

        shared = SHARED_EXAMPLE_METHODS.include?(node.name)
        example_block = EXAMPLE_METHODS.include?(node.name) && node.block
        return unless shared || example_block

        location = node.location

        Example.new(
          description: description_for(node),
          line_number: location.start_line,
          body: @lines[(location.start_line - 1)..(location.end_line - 1)].join,
          shared: shared
        )
      end

      def description_for(node)
        argument = node.arguments&.arguments&.first

        case argument
        when Prism::StringNode
          argument.unescaped
        when Prism::InterpolatedStringNode
          argument.slice[1...-1]
        else
          # `it { ... }` and `specify do` have no description, but they still count as examples.
          "(no description, line #{node.location.start_line})"
        end
      end
    end
  end
end
