# frozen_string_literal: true

# rubocop:disable Scalability/IdempotentWorker -- existing class moved from EE to CE
# rubocop:disable Gitlab/BoundedContexts -- existing class moved from EE to CE
# rubocop:disable Gitlab/NamespacedClass -- existing class moved from EE to CE
class AdjournedGroupDeletionWorker
  include ::Gitlab::InternalEventsTracking
  include ApplicationWorker

  data_consistency :sticky

  include CronjobQueue

  INTERVAL = 20.seconds.to_i

  feature_category :groups_and_projects

  def perform
    deletion_cutoff = Gitlab::CurrentSettings.deletion_adjourned_period.days.ago.to_date
    # Only groups that get a destroy job take a delay slot, so restored or stuck groups
    # do not push back the healthy ones behind them.
    destroys_scheduled = 0

    Group.with_route
      .deletion_scheduled_before(deletion_cutoff)
      .with_deletion_scheduled_by_user
      .find_each(batch_size: 100) do |group| # rubocop: disable CodeReuse/ActiveRecord -- existing class moved from EE to CE
      destroys_scheduled += 1 if process_group(group, destroys_scheduled * INTERVAL)
    end
  end

  private

  def process_group(group, delay)
    user = group.deletion_scheduled_by_user

    with_context(namespace: group, user: user) do
      track_event(group, user)

      result = Namespaces::Groups::AdjournedDeletionService
        .new(group: group, current_user: user, params: { delay: delay })
        .execute

      result.payload[:destroy_scheduled] == true
    rescue StandardError => e
      # One failing group must not end the run and skip every group after it.
      Gitlab::ErrorTracking.track_exception(e, Labkit::Fields::GL_NAMESPACE_ID => group.id)

      false
    end
  end

  def track_event(group, user)
    track_internal_event(
      'trigger_delete_on_group',
      namespace: group,
      user: user,
      label: 'worker',
      property: 'true',
      actor: 'system'
    )
  end
end
# rubocop:enable Scalability/IdempotentWorker
# rubocop:enable Gitlab/BoundedContexts
# rubocop:enable Gitlab/NamespacedClass
