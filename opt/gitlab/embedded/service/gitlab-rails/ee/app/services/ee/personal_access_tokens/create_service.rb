# frozen_string_literal: true

module EE
  module PersonalAccessTokens
    module CreateService
      extend ::Gitlab::Utils::Override

      def execute
        super.tap do |response|
          send_audit_event(response)
        end
      end

      private

      def send_audit_event(response)
        message = if response.success?
                    "Created personal access token with id #{response.payload[:personal_access_token].id}"
                  else
                    "Attempted to create personal access token but failed with message: #{response.message}"
                  end

        audit_context = {
          name: 'personal_access_token_created',
          author: current_user,
          scope: current_user,
          target: target_user,
          message: message
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      override :pat_expiration
      def pat_expiration
        return params[:expires_at] if params[:expires_at].present?

        return unless EE::Gitlab::PersonalAccessTokens::ServiceAccountTokenValidator.new(target_user).expiry_enforced?

        max_expiry_date
      end

      override :max_expiry_date
      def max_expiry_date
        EE::Gitlab::PersonalAccessTokens::ExpiryDateCalculator.new(target_user).max_expiry_date || super
      end
    end
  end
end
