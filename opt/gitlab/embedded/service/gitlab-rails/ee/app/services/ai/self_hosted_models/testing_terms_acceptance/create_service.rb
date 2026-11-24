# frozen_string_literal: true

module Ai
  module SelfHostedModels
    module TestingTermsAcceptance
      class CreateService
        def initialize(current_user)
          @user = current_user
        end

        def execute
          @testing_terms_acceptance = ::Ai::TestingTermsAcceptance.new(user_id: @user.id, user_email: @user.email)

          if @testing_terms_acceptance.save
            audit_event(@testing_terms_acceptance)

            ServiceResponse.success(payload: @testing_terms_acceptance)
          else
            ServiceResponse.error(message: @testing_terms_acceptance.errors.full_messages.join(", "))
          end
        end

        private

        def audit_event(testing_terms_acceptance)
          audit_context = {
            name: 'self_hosted_model_terms_accepted',
            author: @user,
            scope: Gitlab::Audit::InstanceScope.new,
            target: testing_terms_acceptance,
            message: "Self-hosted model testing terms accepted by user - ID: #{@user.id}, email: #{@user.email}"
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end
