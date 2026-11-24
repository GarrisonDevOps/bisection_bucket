# frozen_string_literal: true

module Gitlab
  module Duo
    module CodeReview
      module Modes
        class Base
          def initialize(user:, container:)
            @user = user
            @container = container
          end

          def mode
            raise NotImplementedError
          end

          def enabled?
            raise NotImplementedError
          end

          def active?
            raise NotImplementedError
          end

          private

          attr_reader :user, :container
        end
      end
    end
  end
end
