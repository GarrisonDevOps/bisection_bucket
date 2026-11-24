# frozen_string_literal: true

require_relative 'example_parser'
require_relative 'classifier'

module Tooling
  module FeTestJanitor
    # Analyzes a single *_spec.rb file: parses examples and classifies each one.
    class FileAnalyzer
      FileResult = Struct.new(:path, :example_results, keyword_init: true)
      ExampleResult = Struct.new(:example, :classification, keyword_init: true)

      def initialize(path)
        @path = path
      end

      def analyze
        source = File.read(@path)
        examples = begin
          ExampleParser.new(source).parse
        rescue ExampleParser::ParseError => e
          raise ExampleParser::ParseError, "could not parse #{@path}: #{e.message}"
        end

        classifier = Classifier.new

        example_results = examples.map do |example|
          classification = classifier.classify(example)
          ExampleResult.new(example: example, classification: classification)
        end

        FileResult.new(path: @path, example_results: example_results)
      end
    end
  end
end
