# frozen_string_literal: true

module Gitlab
  module Duo
    module Chat
      module AgentEvents
        class FinalAnswerDelta < BaseEvent
          def text
            data["text"]
          end

          def finish_reason
            data["finish_reason"]
          end
        end
      end
    end
  end
end
