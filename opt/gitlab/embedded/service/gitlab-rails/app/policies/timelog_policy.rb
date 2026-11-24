# frozen_string_literal: true

class TimelogPolicy < BasePolicy
  # The timelog's issue, merge request and project fields authorize too, so they share one project instance.
  def self.preload_for_batch_checks(timelogs, user)
    ActiveRecord::Associations::Preloader.new(
      records: timelogs,
      associations: [{ project: :organization, issue: :project, merge_request: :target_project }]
    ).call

    ::Ability.preload_for_batch_checks(user, timelogs.filter_map(&:issue))
    ::Ability.preload_for_batch_checks(user, timelogs.filter_map(&:merge_request))
  end

  delegate { @subject.issuable }

  desc "User who created the timelog"
  condition(:is_author) { @user && @subject.user == @user }

  rule { is_author & can?(:_delete_authored_timelog) }.policy do
    enable :delete_timelog

    # Backs the adminTimelog GraphQL field, which clients outside the web UI may query.
    enable :admin_timelog
  end
end
