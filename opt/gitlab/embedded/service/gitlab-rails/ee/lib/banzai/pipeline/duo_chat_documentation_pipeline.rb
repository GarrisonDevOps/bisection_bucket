# frozen_string_literal: true

module Banzai
  module Pipeline
    class DuoChatDocumentationPipeline < ::Banzai::Pipeline::PlainMarkdownPipeline
      def self.filters
        [
          *super,
          Banzai::Filter::AbsoluteDocumentationLinkFilter
        ]
      end
    end
  end
end
