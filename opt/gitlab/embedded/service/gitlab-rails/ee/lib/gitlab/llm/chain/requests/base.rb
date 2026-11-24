# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Requests
        class Base
          include ::Gitlab::Llm::Concerns::Logger

          def self.prompt(prompt, options: {})
            { prompt: prompt, options: options }
          end
        end
      end
    end
  end
end
