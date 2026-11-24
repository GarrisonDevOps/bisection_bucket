# frozen_string_literal: true

class Groups::IssuesController < Groups::BulkUpdateController
  feature_category :team_planning
  urgency :low

  before_action :disable_query_limit!, only: :bulk_update

  private

  def disable_query_limit!
    # As of https://gitlab.com/gitlab-org/gitlab/-/jobs/7162705551, this was
    # exceeding 300 queries. 432 -> 433: the ProjectPolicy scheduled-for-deletion condition, see
    # https://gitlab.com/groups/gitlab-org/-/work_items/21607.
    Gitlab::QueryLimiting.disable!('https://gitlab.com/gitlab-org/gitlab/-/issues/390722', new_threshold: 433)
  end
end
