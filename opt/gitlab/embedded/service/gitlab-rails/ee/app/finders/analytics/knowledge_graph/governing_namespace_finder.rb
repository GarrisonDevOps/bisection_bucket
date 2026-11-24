# frozen_string_literal: true

module Analytics
  module KnowledgeGraph
    class GoverningNamespaceFinder
      include Gitlab::Utils::StrongMemoize

      def self.for(user)
        ::Gitlab::SafeRequestStore.fetch([:orbit_governing_namespace_finder, user.id]) { new(user) }
      end

      def initialize(user)
        @user = user
      end

      def candidates
        ::Group.id_in(candidate_ids)
      end

      def eligible?(namespace_id)
        return false unless namespace_id

        candidate_ids.include?(namespace_id.to_i)
      end

      def single_candidate_fallback
        ::Group.find_by_id(candidate_ids.first) if candidate_ids.one?
      end

      private

      attr_reader :user

      def candidate_ids
        return [] unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        root_ids = ::Analytics::Orbit::MemberGroups.for(user).on_root_ids - user.namespace_bans.map(&:namespace_id)
        gated_root_ids = ::Analytics::Orbit::Billing.promo_gated_root_ids(root_ids)

        paid_root_ids = ::GitlabSubscription
          .with_hosted_plan([::GitlabSubscriptions::SystemDefined::Plan::PREMIUM, ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE])
          .namespace_id_in(root_ids - gated_root_ids)
          .select(:namespace_id)

        ::Group.id_in(paid_root_ids).pluck_primary_key | gated_root_ids
      end
      strong_memoize_attr :candidate_ids
    end
  end
end
