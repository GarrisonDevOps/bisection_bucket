# frozen_string_literal: true

module Analytics
  module Orbit
    module Billing
      def self.account_for(group)
        return instance_account unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        root = group.root_ancestor
        ::Gitlab::SafeRequestStore.fetch([:orbit_billing_group_account, root.id]) { GroupAccount.new(root) }
      end

      def self.instance_account
        ::Gitlab::SafeRequestStore.fetch(:orbit_billing_instance_account) { InstanceAccount.new }
      end

      # Batch forms of the rules in Account#entitled?, so a rule change there must change them too.
      def self.promo_gated_root_ids(root_ids)
        root_ids.select { |id| GroupAccount.promo_gate_for?(::Group.actor_from_id(id)) }
      end

      def self.reject_gated_root_ids_without_access(root_ids)
        root_ids - gated_root_ids_without_access(root_ids)
      end

      def self.gated_root_ids_without_access(root_ids)
        gated_ids = promo_gated_root_ids(root_ids)
        gated_ids - promo_entitled_root_ids(gated_ids)
      end

      def self.any_entitled_root?(root_ids)
        return false if root_ids.empty?

        roots = ::Group.id_in(root_ids).include_gitlab_subscription_with_hosted_plan.to_a
        gated_roots, plan_tier_roots = roots.partition { |root| GroupAccount.promo_gate_for?(root) }

        plan_tier_roots.any? { |root| root.licensed_feature_available?(:orbit) } ||
          promo_entitled_root_ids(gated_roots.map(&:id)).any?
      end

      # The ended-trials cron only checks roots with Orbit on, so only their trial rows are current.
      def self.promo_entitled_root_ids(root_ids)
        return [] if root_ids.empty?

        add_on_root_ids = ::GitlabSubscriptions::AddOnPurchase.for_orbit_promo.active
          .by_namespace(root_ids).uniq_namespace_ids
        enabled_namespaces = ::Analytics::KnowledgeGraph::EnabledNamespace.for_root_namespace_id(root_ids)
        trial_root_ids = NamespaceEnrollment.trials_not_ended_for(enabled_namespaces).pluck_primary_key

        add_on_root_ids | trial_root_ids
      end
      private_class_method :promo_entitled_root_ids
    end
  end
end
