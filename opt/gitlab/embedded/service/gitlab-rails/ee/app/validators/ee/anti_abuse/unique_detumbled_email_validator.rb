# frozen_string_literal: true

module EE
  module AntiAbuse
    module UniqueDetumbledEmailValidator
      extend ::Gitlab::Utils::Override
      include ::GitlabSubscriptions::SubscriptionHelper

      private

      override :limit_normalized_email_reuse?
      def limit_normalized_email_reuse?(email)
        super && !paid_verified_domain?(email)
      end

      def paid_verified_domain?(email)
        return false unless gitlab_com_subscription?

        email_domain = Mail::Address.new(email).domain.downcase

        return true if email_domain == ::Gitlab.root_domain

        root_group = ::PagesDomain.verified.find_by_domain_case_insensitive(email_domain)&.root_group

        !!root_group&.paid?
      end
    end
  end
end
