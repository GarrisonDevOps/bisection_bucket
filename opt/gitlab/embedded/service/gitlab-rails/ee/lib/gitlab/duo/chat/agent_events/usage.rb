# frozen_string_literal: true

module Gitlab
  module Duo
    module Chat
      module AgentEvents
        class Usage < BaseEvent
          # Token counts keyed by model, in the shape
          # { "<model>" => { "input_tokens" => Integer, "output_tokens" => Integer } }.
          #
          # Kept per model rather than summed because counts are not equivalent across
          # models, so a total would not be a meaningful figure.
          def usage
            data["usage"]
          end

          # The gateway emits this once, after the answer stream is exhausted.
          def metadata?
            true
          end
        end
      end
    end
  end
end
