# frozen_string_literal: true

class GitlabSubscription < ApplicationRecord
  include Gitlab::Utils::StrongMemoize
  include AfterCommitQueue
  include ::GitlabSubscriptions::Billing::GitlabSubscription
  include ActiveRecord::FixedItemsModel::HasOne

  SUBSCRIPTION_GRACE_PERIOD = 14.days.freeze
  ZOEKT_ELIGIBILITY_ATTRIBUTES = %w[hosted_plan_name_uid trial trial_ends_on end_date].freeze

  enum :trial_extension_type, { extended: 1, reactivated: 2 }

  attribute :start_date, default: -> { Time.zone.today }

  before_validation :set_hosted_plan_name_uid

  before_update :set_max_seats_used_changed_at
  before_update :log_previous_state_for_update, if: :tracked_attributes_changed?
  before_update :reset_seat_statistics
  before_update :publish_subscription_renewed_event

  after_commit :reset_seats_usage_callouts, on: :update
  after_commit :index_namespace, on: [:create, :update]
  after_commit :enable_zoekt_namespace, on: [:create, :update]
  after_destroy_commit :log_previous_state_for_destroy

  belongs_to :namespace
  belongs_to_fixed_items :hosted_plan, fixed_items_class: ::GitlabSubscriptions::SystemDefined::Plan,
    foreign_key: 'hosted_plan_name_uid'
  has_one :organization_gitlab_subscription,
    class_name: 'Organizations::OrganizationGitlabSubscription',
    inverse_of: :gitlab_subscription

  validates :seats, :start_date, presence: true
  validates :namespace_id, uniqueness: true, presence: true

  validates :trial_ends_on, :trial_starts_on, presence: true, if: :trial?
  validates_comparison_of :trial_ends_on, greater_than: :trial_starts_on, if: :trial?
  validates :hosted_plan_name_uid, presence: true, if: :hosted_plan_id?
  validates :hosted_plan_name_uid,
    inclusion: { in: ::GitlabSubscriptions::SystemDefined::Plan.all.map(&:id) }, allow_nil: true
  validates :contract_overages_allowed, inclusion: { in: [true, false] }

  delegate :name, :title, to: :hosted_plan, prefix: :plan, allow_nil: true
  delegate :exclude_guests?, to: :namespace

  scope :by_hosted_plan_name_uids, ->(plan_name_uids) do
    where(hosted_plan_name_uid: plan_name_uids)
  end

  scope :with_hosted_plan, ->(plan_name) do
    by_hosted_plan_name_uids(::GitlabSubscriptions::SystemDefined::Plan.uids_for_names(plan_name))
      .where(trial: [false, nil])
  end

  scope :with_a_paid_hosted_plan, -> do
    with_hosted_plan(::GitlabSubscriptions::SystemDefined::Plan::PAID_HOSTED_PLANS)
  end

  scope :with_a_paid_or_trial_hosted_plan, -> do
    by_hosted_plan_name_uids(::GitlabSubscriptions::SystemDefined::Plan.uids_for_names(::GitlabSubscriptions::SystemDefined::Plan::PAID_HOSTED_PLANS))
  end

  scope :with_active_paid_or_trial_hosted_plan, ->(grace_period = 0) do
    with_a_paid_hosted_plan.not_expired(before_date: Date.current - grace_period).or(
      with_a_paid_or_trial_hosted_plan.where(trial: true, trial_ends_on: (Date.current - grace_period)..)
    )
  end
  scope :id_greater_than, ->(id) { where(arel_table[:id].gt(id)) }
  scope :with_namespace_settings, -> { joins(namespace: :namespace_settings).includes(namespace: :namespace_settings) }

  scope :max_seats_used_changed_between, ->(from:, to:) do
    where(max_seats_used_changed_at: from..to)
  end

  scope :not_expired, ->(before_date: Time.zone.today) { where('end_date IS NULL OR end_date >= ?', before_date) }

  scope :namespace_id_in, ->(namespace_ids) do
    where(namespace_id: namespace_ids)
  end

  def self.many_active_paid_or_trial_for_namespaces?(namespace_ids)
    namespace_id_in(namespace_ids).with_active_paid_or_trial_hosted_plan.many?
  end

  scope :with_ultimate_trial_ending_on, ->(date) do
    plan_uids = ::GitlabSubscriptions::SystemDefined::Plan.uids_for_names(
      ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE_TRIAL_PLANS
    )

    by_hosted_plan_name_uids(plan_uids).where(trial: true, trial_ends_on: date)
  end

  scope :preload_namespace_with_route, -> { preload(namespace: :route) }

  # The purpose of max_seats_used is similar to what we do for EE licenses
  # with the historical max. We want to know how many extra users the customer
  # has added to their group (users above the number purchased on their subscription).
  # Then, on the next month we're going to automatically charge the customers for those extra users.
  def calculate_seats_owed
    return 0 unless has_a_paid_hosted_plan?

    [0, max_seats_used - seats].max
  end

  def seats_remaining
    [0, seats - max_seats_used.to_i].max
  end

  def has_a_paid_hosted_plan?
    !trial? && seats > 0 && ::GitlabSubscriptions::SystemDefined::Plan::PAID_HOSTED_PLANS.include?(plan_name)
  end

  def expired?
    return false unless end_date

    end_date < Date.current
  end

  def paid_and_expired?
    has_a_paid_hosted_plan? && expired?
  end

  def active_paid_or_trial?
    return false unless hosted_plan&.paid?
    return trial_ends_on.present? && trial_ends_on >= Date.current if trial?

    !expired?
  end

  def upgradable?
    return false if ::GitlabSubscriptions::SystemDefined::Plan::TOP_PLANS.include?(plan_name)

    has_a_paid_hosted_plan? && !expired?
  end

  def plan_code=(code)
    code ||= ::GitlabSubscriptions::SystemDefined::Plan::FREE

    self.hosted_plan = ::GitlabSubscriptions::SystemDefined::Plan.find_by(name: code)
  end

  # belongs_to_fixed_items writes `plan.id` as the uid, which for an AR Plan is
  # its plans.id. Take an AR Plan's uid instead, as the AR association did.
  def hosted_plan=(plan)
    self.hosted_plan_name_uid =
      case plan
      when nil then nil
      when ::GitlabSubscriptions::SystemDefined::Plan then plan.id
      when ::Plan then plan.plan_name_uid_before_type_cast
      else
        raise ActiveRecord::AssociationTypeMismatch,
          "GitlabSubscriptions::SystemDefined::Plan or Plan expected, got #{plan.inspect} " \
            "which is an instance of #{plan.class}"
      end
  end

  def trial_extended_or_reactivated?
    trial_extension_type.present?
  end

  private

  def log_previous_state_for_update
    attrs = attributes.merge(attributes_in_database)

    GitlabSubscriptions::SubscriptionHistory.create_from_change(:gitlab_subscription_updated, attrs)
  end

  def log_previous_state_for_destroy
    GitlabSubscriptions::SubscriptionHistory.create_from_change(:gitlab_subscription_destroyed, attributes)
  end

  def automatically_index_in_elasticsearch?
    return false unless ::Gitlab::Saas.feature_available?(:advanced_search)
    return false if expired?

    # We only index paid groups or trials on dot com for now.
    ::GitlabSubscriptions::SystemDefined::Plan::PAID_HOSTED_PLANS.include?(plan_name)
  end

  # Kick off Elasticsearch indexing for paid groups with new or upgraded paid, hosted subscriptions
  # Uses safe_find_or_create_by to avoid ActiveRecord::RecordNotUnique exception when upgrading from
  # one paid plan to another paid plan
  def index_namespace
    return unless automatically_index_in_elasticsearch?

    ElasticsearchIndexedNamespace.safe_find_or_create_by!(namespace_id: namespace_id)
  end

  def enable_zoekt_namespace
    return unless automatically_enable_zoekt?

    inserted = ::Search::Zoekt::EnabledNamespace.insert_all(
      [{ root_namespace_id: namespace_id }], unique_by: :root_namespace_id
    )
    ::Search::Zoekt::RolloutWorker.perform_async if inserted.rows.any?
  rescue StandardError => e
    # Raising here would skip the remaining after_commit callbacks. The SaaS rollout sweep retries the namespace.
    ::Gitlab::ErrorTracking.track_exception(e, namespace_id: namespace_id)
  end

  def automatically_enable_zoekt?
    return false unless saved_changes.keys.intersect?(ZOEKT_ELIGIBILITY_ATTRIBUTES)
    return false unless ::Gitlab::Saas.feature_available?(:exact_code_search)
    return false unless ::Search::Zoekt.licensed_and_indexing_enabled?
    return false unless namespace.root?
    return false unless Feature.enabled?(:zoekt_enable_namespace_on_subscription_change, namespace)

    active_paid_or_trial?
  end

  # If the subscription changes, we reset max_seats_used and seats_owed
  # if they're out of date, so that we don't carry them over from the previous term/subscription.
  # One exception is the plan switch between `premium` and `ultimate_trial_paid_customer`.
  def reset_seat_statistics
    return unless reset_seat_statistics?

    refresh_seat_attributes(reset_max: true)
    self.max_seats_used_changed_at = Time.current
  end

  def publish_subscription_renewed_event
    return unless new_term?

    run_after_commit do
      Gitlab::EventStore.publish(GitlabSubscriptions::RenewedEvent.new(data: { namespace_id: namespace_id }))
    end
  end

  def set_max_seats_used_changed_at
    return if new_term? || !max_seats_used_changed?

    self.max_seats_used_changed_at = Time.current
  end

  def new_term?
    persisted? && start_date_changed? && end_date_changed? &&
      (end_date_was.nil? || start_date >= end_date_was)
  end

  def reset_seat_statistics?
    return reset_involves_ultimate_trial_paid_customer_plan? if involves_ultimate_trial_paid_customer_plan?
    return false unless has_a_paid_hosted_plan?
    return true if new_term?
    return true if trial_changed? && !trial

    max_seats_used_changed_at.present? && max_seats_used_changed_at.to_date < start_date
  end

  def ultimate_trial_paid_customer_uid
    ::GitlabSubscriptions::SystemDefined::Plan.find_by(name: ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE_TRIAL_PAID_CUSTOMER).id
  end

  def premium_plan_uid
    ::GitlabSubscriptions::SystemDefined::Plan.find_by(name: ::GitlabSubscriptions::SystemDefined::Plan::PREMIUM).id
  end

  def involves_ultimate_trial_paid_customer_plan?
    ultimate_trial_paid_customer_uid.in?([hosted_plan_name_uid, hosted_plan_name_uid_was])
  end

  def reset_involves_ultimate_trial_paid_customer_plan?
    # Do not reset if plan unchanged on ultimate_trial_paid_customer_plan
    return false unless hosted_plan_name_uid_changed?

    # Do not reset if switching to ultimate_trial_paid_customer_plan
    return false if hosted_plan_name_uid == ultimate_trial_paid_customer_uid

    # Now hosted_plan_name_uid_was must be the ultimate_trial_paid_customer uid
    return false if hosted_plan_name_uid == premium_plan_uid && premium_plan_not_renewed?

    # Either the premium plan was renewed, or it is upgrading to ultimate plan
    true
  end

  def premium_plan_not_renewed?
    previous_premium_gs = GitlabSubscriptions::SubscriptionHistory
                            .where(gitlab_subscription_id: id, hosted_plan_name_uid: premium_plan_uid).order(:id).last

    previous_premium_gs&.start_date == start_date && previous_premium_gs&.end_date == end_date
  end

  def tracked_attributes_changed?
    changed.intersection(GitlabSubscriptions::SubscriptionHistory::TRACKED_ATTRIBUTES).any?
  end

  def reset_seats_usage_callouts
    return unless saved_change_to_seats?

    Groups::ResetSeatCalloutsWorker.perform_async(namespace_id)
  end

  # The previous release reads the plan through hosted_plan_id, so keep both
  # columns in step, both ways, until every node reads the uid. Stop the
  # hosted_plan_id half with https://gitlab.com/gitlab-org/gitlab/-/work_items/600315.
  def set_hosted_plan_name_uid
    if hosted_plan_name_uid_changed?
      self.hosted_plan_id = hosted_plan_name_uid && ::Plan.find_by(plan_name_uid: hosted_plan_name_uid)&.id
    elsif hosted_plan_name_uid.blank? || hosted_plan_id_changed?
      self.hosted_plan_name_uid = hosted_plan_id && ::Plan.find_by(id: hosted_plan_id)&.plan_name_uid_before_type_cast
    end
  end
end

# Added for JiHu
# Used in https://jihulab.com/gitlab-cn/gitlab/-/blob/main-jh/jh/app/models/jh/gitlab_subscription.rb
GitlabSubscription.prepend_mod
