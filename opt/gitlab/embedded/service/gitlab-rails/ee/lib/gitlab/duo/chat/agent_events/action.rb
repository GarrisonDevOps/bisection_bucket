# frozen_string_literal: true

module Gitlab
  module Duo
    module Chat
      module AgentEvents
        class Action < BaseEvent
          def thought
            data["thought"]
          end

          def tool
            data["tool"]
          end

          def tool_input
            data["tool_input"]
          end
        end
      end
    end
  end
end
