# frozen_string_literal: true

module Gitlab
  module Llm
    module PromptResolvers
      class ReviewMergeRequest < Base
        class << self
          def execute(_user: nil, _project: nil, _group: nil)
            if ::Ai::AmazonQ.enabled?
              'amazon_q/1.0.0' # Amazon Q
            else
              '1.3.0' # Claude 4.0 Sonnet
            end
          end
        end
      end
    end
  end
end
