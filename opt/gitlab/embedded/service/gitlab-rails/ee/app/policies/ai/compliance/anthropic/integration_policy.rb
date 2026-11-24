# frozen_string_literal: true

module Ai
  module Compliance
    module Anthropic
      class IntegrationPolicy < ::BasePolicy
        delegate { @subject.namespace }
      end
    end
  end
end
