# frozen_string_literal: true

module Analytics
  module KnowledgeGraph
    module OrbitLicense
      CACHE_KEY = 'orbit_feature_licensed'
      POSITIVE_CACHE_PERIOD = 30.minutes
      NEGATIVE_CACHE_PERIOD = 2.minutes

      def self.available_for?(user)
        return false unless user

        unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
          return ::Analytics::Orbit::Billing.instance_account.entitled?
        end

        key = ['users', user.id, CACHE_KEY]

        cached = Rails.cache.read(key)
        return cached unless cached.nil?

        root_ids = ::Analytics::Orbit::MemberGroups.for(user).root_ids
        orbit_available = ::Analytics::Orbit::Billing.any_entitled_root?(root_ids)

        Rails.cache.write(
          key,
          orbit_available,
          expires_in: orbit_available ? POSITIVE_CACHE_PERIOD : NEGATIVE_CACHE_PERIOD
        )

        orbit_available
      end

      # Orbit bills only queries, so on an instance the license is enough to read graph status.
      def self.status_available_for?(user)
        return false unless user
        return available_for?(user) if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        ::Analytics::Orbit::Billing.instance_account.eligible?
      end

      def self.entitled?(resource)
        ::Analytics::Orbit::Billing.account_for(resource).entitled?(resource)
      end
    end
  end
end
