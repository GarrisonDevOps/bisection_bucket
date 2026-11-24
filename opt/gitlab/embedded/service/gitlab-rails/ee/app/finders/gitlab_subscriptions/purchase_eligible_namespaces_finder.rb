# frozen_string_literal: true

# Finds namespaces and filters them by their eligibility to purchase a new subscription.
#
# - When `namespace_id: ID` is supplied, this will also be used to filter the namespaces.
# - When `plan_id: ID` is supplied the eligibility will be checked for that specific plan ID.
#   This param should be supplied when checking add on pack eligibility. If blank, the
#   eligibility to have a new self-service plan (ie Premium/Ultimate) in general is checked.
module GitlabSubscriptions
  class PurchaseEligibleNamespacesFinder
    def initialize(user:, namespace_id: nil, plan_id: nil, check_subscription_status: true)
      @user = user
      @namespace_id = namespace_id
      @plan_id = plan_id.presence
      @check_subscription_status = check_subscription_status
    end

    def execute
      return Namespace.none unless user.present?

      candidate_namespaces = user.owned_groups.top_level.with_counts(archived: false)
      candidate_namespaces = candidate_namespaces.id_in(namespace_id) if namespace_id.present?

      return Namespace.none unless candidate_namespaces.exists?

      if check_subscription_status
        eligible_ids = fetch_eligibility_data(candidate_namespaces)

        candidate_namespaces.id_in(eligible_ids)
      else
        candidate_namespaces
      end
    end

    private

    attr_reader :user, :namespace_id, :plan_id, :check_subscription_status

    def fetch_eligibility_data(namespaces)
      params = { plan_id: plan_id, any_self_service_plan: plan_id.nil? }.compact_blank

      response = Gitlab::SubscriptionPortal::Client.filter_purchase_eligible_namespaces(namespaces, **params)

      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- False positive on an Array.
      # rubocop:disable CodeReuse/ActiveRecord -- False positive on an Array.
      response[:data].pluck('id') if response[:success] && response[:data]
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit -- False positive on an Array.
      # rubocop:enable CodeReuse/ActiveRecord -- False positive on an Array.
    end
  end
end
