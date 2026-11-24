# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    class LdapAddOnSeatSyncWorker
      include ApplicationWorker
      include GitlabSubscriptions::AddOnPurchases::UserAddOnAssignmentCommon

      data_consistency :sticky
      feature_category :seat_cost_management
      idempotent!

      def perform(params = {})
        @user_id = params['user_id']
        @root_namespace_id = nil # LDAP is only enabled for self-managed

        return unless user && ldap_identity && provider

        return unless ldap_config.duo_add_on_groups.present?

        return unless add_on_purchase&.active?

        if in_any_duo_add_on_groups?
          GitlabSubscriptions::UserAddOnAssignments::SelfManaged::CreateService.new(
            add_on_purchase: add_on_purchase,
            user: user
          ).execute
        else
          GitlabSubscriptions::Duo::BulkUnassignService.new(
            add_on_purchase: add_on_purchase,
            user_ids: [user.id]
          ).execute
        end
      end

      private

      def ldap_identity
        @ldap_identity ||= user.ldap_identity
      end

      def provider
        @provider ||= ldap_identity.provider
      end

      def ldap_config
        @ldap_config ||= ::Gitlab::Auth::Ldap::Config.new(provider)
      end

      def in_any_duo_add_on_groups?
        ::EE::Gitlab::Auth::Ldap::Sync::Proxy.open(provider) do |proxy|
          duo_add_on_groups = proxy.adapter.config.duo_add_on_groups

          duo_add_on_groups.any? do |group_cn|
            member_dns = proxy.dns_for_group_cn(group_cn)
            member_dns.include?(ldap_identity.extern_uid)
          end
        end
      end
    end
  end
end
