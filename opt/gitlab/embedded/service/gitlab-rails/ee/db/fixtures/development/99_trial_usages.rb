# frozen_string_literal: true

# Nothing writes to this table until the capture worker lands (see
# https://gitlab.com/gitlab-org/gitlab/-/work_items/625030). This fixture exists so
# db:migrate:multi-version-upgrade has a row to exercise.
Gitlab::Seeder.quiet do
  group = Group.top_level.first
  next warn "\nSkipping trial_usages seeds: no top-level group available" unless group

  GitlabSubscriptions::TrialUsage.find_or_create_by!(namespace: group, trial_ends_on: 30.days.ago.to_date) do |usage|
    usage.trial_starts_on = 60.days.ago.to_date
    usage.compute_minutes_month = 60.days.ago.to_date.beginning_of_month
    usage.max_seats_used = 3
    usage.compute_minutes_used = 250
    usage.credits_used = 12.5
    usage.trial_type = GitlabSubscriptions::Trials::FREE_TRIAL_TYPE_V2
  end

  print '.'
end
