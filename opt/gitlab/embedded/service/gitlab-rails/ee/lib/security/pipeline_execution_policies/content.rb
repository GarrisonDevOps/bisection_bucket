# frozen_string_literal: true

module Security
  module PipelineExecutionPolicies
    class Content
      def initialize(content)
        @content = content || {}
      end

      def include
        (content[:include] || []).map do |item|
          Security::PipelineExecutionPolicies::Include.new(item)
        end
      end

      private

      attr_reader :content
    end
  end
end
