# frozen_string_literal: true

module Groups
  module EnterpriseUsers
    class BulkAssociateByDomainWorker
      include ApplicationWorker

      idempotent!
      feature_category :user_management
      data_consistency :sticky

      def perform(pages_domain_id)
        pages_domain = PagesDomain.verified.find_by_id(pages_domain_id)
        return unless pages_domain

        group = pages_domain.root_group
        return unless group
        return unless group.domain_verification_available?

        User.select(:id)
          .human
          .with_email_domain(pages_domain.domain)
          .each_batch(of: 100) do |users|
            ::Groups::EnterpriseUsers::AssociateWorker.bulk_perform_async( # rubocop:disable Scalability/BulkPerformWithContext
              users.excluding_enterprise_users_of_group(group).map { |user| [user.id] }
            )
          end
      end
    end
  end
end
