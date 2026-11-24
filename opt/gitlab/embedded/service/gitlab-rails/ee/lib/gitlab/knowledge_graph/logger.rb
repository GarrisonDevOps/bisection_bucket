# frozen_string_literal: true

module Gitlab
  module KnowledgeGraph
    class Logger < ::Gitlab::JsonLogger
      def self.file_name_noext
        'knowledge_graph'
      end

      private

      def default_attributes
        super.merge(feature_category: :knowledge_graph)
      end
    end
  end
end
