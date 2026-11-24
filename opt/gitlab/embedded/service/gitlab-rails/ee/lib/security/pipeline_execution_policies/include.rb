# frozen_string_literal: true

module Security
  module PipelineExecutionPolicies
    class Include
      def initialize(include_item)
        @include_item = include_item || {}
      end

      def project
        include_item[:project]
      end

      def file
        include_item[:file]
      end

      def ref
        include_item[:ref]
      end

      private

      attr_reader :include_item
    end
  end
end
