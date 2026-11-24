# frozen_string_literal: true

# GitlabSubscriptions::SubscriptionHistory records the previous value before change.
module GitlabSubscriptions
  class SubscriptionHistory < ApplicationRecord
    include ActiveRecord::FixedItemsModel::HasOne

    self.table_name = 'gitlab_subscription_histories'

    # `gitlab_subscription_created` change_type (id: 0) doesn't exist because there's no previous value before creation
    enum :change_type, {
      gitlab_subscription_updated: 1,
      gitlab_subscription_destroyed: 2
    }

    belongs_to :namespace, optional: false
    belongs_to_fixed_items :hosted_plan, fixed_items_class: ::GitlabSubscriptions::SystemDefined::Plan,
      foreign_key: 'hosted_plan_name_uid'

    validates :gitlab_subscription_id, presence: true

    PREFIXED_ATTRIBUTES = %w[
      id
      created_at
      updated_at
    ].freeze

    TRACKED_ATTRIBUTES = %w[
      start_date
      end_date
      trial_ends_on
      namespace_id
      hosted_plan_id
      hosted_plan_name_uid
      seats_in_use
      max_seats_used
      seats
      trial
      trial_starts_on
      auto_renew
      trial_extension_type
      contract_overages_allowed
    ].freeze

    # Attributes can be added to this list if they should not be tracked by the history table.
    # By default, attributes should be tracked, and only added to this list if there is a
    # good reason not to.
    # We don't use this list other than to raise awareness of which attributes we should not track.
    OMITTED_ATTRIBUTES = %w[
      seats_owed
      max_seats_used_changed_at
      last_seat_refresh_at
    ].freeze

    scope :with_all_ultimate_plans, -> do
      where(hosted_plan_name_uid: ::GitlabSubscriptions::SystemDefined::Plan.uids_for_names(::GitlabSubscriptions::SystemDefined::Plan::ALL_ULTIMATE_PLANS))
    end

    # Rows without a plan count as unpaid: the stricter choice for callers that
    # measure how long a namespace has been paying. An Ultimate trial for a
    # paying customer is flagged as a trial but is still paid.
    scope :without_paid_plan_excluding_trials, -> do
      plan = ::GitlabSubscriptions::SystemDefined::Plan
      paid_plan_uids = plan.uids_for_names(plan::PAID_HOSTED_PLANS - plan::FREE_TRIAL_PLANS)
      paid_customer_trial_uids = plan.uids_for_names(plan::ULTIMATE_TRIAL_PAID_CUSTOMER)

      where.not(hosted_plan_name_uid: paid_plan_uids)
        .or(where(hosted_plan_name_uid: nil))
        .or(where(trial: true).where.not(hosted_plan_name_uid: paid_customer_trial_uids))
    end

    scope :created_since, ->(time) { where(created_at: time..) }

    scope :ended_on, ->(date) { where(end_date: date) }

    scope :with_namespace_subscription, -> { includes(namespace: :gitlab_subscription) }

    def self.create_from_change(change_type, attrs)
      create_attrs = attrs
        .slice(*TRACKED_ATTRIBUTES)
        .merge(change_type: change_type)

      PREFIXED_ATTRIBUTES.each do |attr_name|
        create_attrs["gitlab_subscription_#{attr_name}"] = attrs[attr_name]
      end

      create(create_attrs)
    end

    def declarative_policy_subject
      namespace
    end
  end
end
