# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module Signals
        module Registry
          extend ActiveSupport::Concern

          included do |base|
            base.class_attribute(:registered_signals, default: [])
          end

          class_methods do
            def register_signal(extractor_class)
              self.registered_signals += [extractor_class]
            end
          end
        end
      end
    end
  end
end
