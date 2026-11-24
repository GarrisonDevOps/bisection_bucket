# frozen_string_literal: true

module Gitlab
  module Duo
    module CodeReview
      module Modes
        class Disabled < Base
          def mode
            :disabled
          end

          def enabled?
            false
          end

          def active?
            true
          end
        end
      end
    end
  end
end
