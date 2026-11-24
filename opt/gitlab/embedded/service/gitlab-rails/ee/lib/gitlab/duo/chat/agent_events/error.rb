# frozen_string_literal: true

module Gitlab
  module Duo
    module Chat
      module AgentEvents
        class Error < BaseEvent
          def message
            data["message"]
          end

          def retryable?
            data["retryable"] || false
          end
        end
      end
    end
  end
end
