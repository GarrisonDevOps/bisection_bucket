# frozen_string_literal: true

module Gitlab
  module Duo
    module Chat
      module AgentEvents
        class BaseEvent
          def initialize(data)
            @data = data
          end

          # Metadata events describe the request rather than carrying part of the answer, so
          # consumers reasoning about the answer itself exclude them.
          def metadata?
            false
          end

          private

          attr_reader :data
        end
      end
    end
  end
end
