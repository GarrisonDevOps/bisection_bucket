# frozen_string_literal: true

module Security
  module ScanExecutionPolicies
    class PipelineSources
      def initialize(pipeline_sources)
        @pipeline_sources = pipeline_sources || {}
      end

      def including
        pipeline_sources[:including] || []
      end

      private

      attr_reader :pipeline_sources
    end
  end
end
