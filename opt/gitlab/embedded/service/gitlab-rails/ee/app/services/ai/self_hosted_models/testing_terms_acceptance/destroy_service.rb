# frozen_string_literal: true

module Ai
  module SelfHostedModels
    module TestingTermsAcceptance
      class DestroyService
        def initialize(testing_terms_acceptance)
          @testing_terms_acceptance = testing_terms_acceptance
        end

        def execute
          if @testing_terms_acceptance.destroy
            ServiceResponse.success(message: 'Testing terms acceptance destroyed')
          else
            ServiceResponse.error(message: @testing_terms_acceptance.errors.full_messages.join(", "))
          end
        end
      end
    end
  end
end
