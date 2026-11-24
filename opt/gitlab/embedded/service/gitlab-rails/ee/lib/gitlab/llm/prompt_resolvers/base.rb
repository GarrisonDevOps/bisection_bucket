# frozen_string_literal: true

module Gitlab
  module Llm
    module PromptResolvers
      class Base
        class << self
          def execute(_user: nil, _project: nil, _group: nil)
            raise NotImplementedError
          end
        end
      end
    end
  end
end
