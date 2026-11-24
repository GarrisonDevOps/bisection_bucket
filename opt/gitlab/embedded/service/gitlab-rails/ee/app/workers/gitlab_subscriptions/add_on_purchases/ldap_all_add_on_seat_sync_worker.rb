# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    class LdapAllAddOnSeatSyncWorker
      include ApplicationWorker
      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- Periodic processing is required

      data_consistency :sticky
      feature_category :seat_cost_management

      deduplicate :until_executed
      idempotent!

      worker_has_external_dependencies!

      def perform
        return unless Gitlab::Auth::Ldap::Config.enabled?
        return unless add_on_purchase.present?

        providers_with_duo_groups = Gitlab::Auth::Ldap::Config.providers.filter_map do |provider|
          config = Gitlab::Auth::Ldap::Config.new(provider)
          provider if config.duo_add_on_groups.present?
        end

        return if providers_with_duo_groups.empty?

        logger.info('Started LDAP Duo seat sync')

        duo_member_dns = fetch_duo_member_dns_from_ldap(providers_with_duo_groups)

        return if duo_member_dns.empty?

        User.ldap.each_batch(of: 100) do |users_batch|
          users_to_assign = []
          users_to_remove = []

          users_batch.each do |user|
            ldap_identity = user.ldap_identity

            if duo_member_dns.include?(ldap_identity.extern_uid)
              users_to_assign << user.id
            else
              users_to_remove << user.id
            end
          end

          if users_to_assign.any?
            GitlabSubscriptions::Duo::BulkAssignService.new(
              add_on_purchase: add_on_purchase,
              user_ids: users_to_assign
            ).execute
          end

          next unless users_to_remove.any?

          GitlabSubscriptions::Duo::BulkUnassignService.new(
            add_on_purchase: add_on_purchase,
            user_ids: users_to_remove
          ).execute
        end

        logger.info('Finished LDAP Duo seat sync')
      end

      private

      def fetch_duo_member_dns_from_ldap(providers_with_duo_groups)
        member_dns = Set.new

        providers_with_duo_groups.each do |provider|
          ::EE::Gitlab::Auth::Ldap::Sync::Proxy.open(provider) do |proxy|
            duo_add_on_groups = proxy.adapter.config.duo_add_on_groups

            duo_add_on_groups.each do |group_cn|
              group_member_dns = proxy.dns_for_group_cn(group_cn)
              member_dns.merge(group_member_dns)
            end
          end
        end

        member_dns
      end

      def add_on_purchase
        @add_on_purchase ||= GitlabSubscriptions::AddOnPurchase
          .for_self_managed
          .for_seat_assignable_duo_add_ons.active
          .first
      end
    end
  end
end
