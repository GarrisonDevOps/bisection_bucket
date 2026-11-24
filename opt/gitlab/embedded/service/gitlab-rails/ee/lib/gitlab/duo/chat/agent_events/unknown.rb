# frozen_string_literal: true

module Gitlab
  module Duo
    module Chat
      module AgentEvents
        class Unknown < BaseEvent
          def text
            data["text"]
          end
        end
      end
    end
  end
end
