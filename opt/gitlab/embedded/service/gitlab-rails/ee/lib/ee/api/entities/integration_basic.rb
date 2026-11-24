# frozen_string_literal: true

module EE
  module API
    module Entities
      module IntegrationBasic
        extend ActiveSupport::Concern

        prepended do
          expose :vulnerability_events, documentation: { type: 'Boolean' }
        end
      end
    end
  end
end
