# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnMetrics
    extend ActiveSupport::Concern

    private

    def generate_add_on_metrics
      active_add_on_purchases_with_seat_counts.map do |purchase|
        add_on_name = GitlabSubscriptions::SystemDefined::AddOn.name_for_uid(purchase.subscription_add_on_uid)

        {
          add_on_type: add_on_name,
          purchased_seats: purchased_seats_for(purchase, add_on_name),
          assigned_seats: purchase.assigned_users_count
        }
      end
    end

    def purchased_seats_for(purchase, add_on_name)
      # GitLab Credits is not a seat-based add-on, so we report 0 purchased seats
      # to avoid confusion with seat-based metrics
      add_on_name == 'gitlab_credits' ? 0 : purchase.quantity
    end

    def active_add_on_purchases_with_seat_counts
      GitlabSubscriptions::AddOnPurchase
        .active
        .by_namespace(nil)
        .left_joins(:assigned_users)
        .select(
          :quantity,
          :subscription_add_on_uid,
          'COUNT(subscription_user_add_on_assignments.id) AS assigned_users_count'
        )
        .group(:id, :subscription_add_on_uid)
    end
  end
end
