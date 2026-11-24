# frozen_string_literal: true

class InstanceSecurityDashboard
  extend ActiveModel::Naming
  include Gitlab::Utils::StrongMemoize

  delegate :full_path, to: :user
  delegate :root_ancestor, to: :duo_enabled_project, allow_nil: true

  attr_reader :user

  def initialize(user)
    @user = user
  end

  def duo_features_enabled
    duo_enabled_project.present?
  end
  alias_method :duo_features_enabled?, :duo_features_enabled

  def feature_available?(feature)
    License.feature_available?(feature)
  end

  def non_archived_project_ids
    limit = UsersSecurityDashboardProject::SECURITY_DASHBOARD_PROJECTS_LIMIT
    projects.non_archived.limit(limit).pluck_primary_key
  end

  # rubocop: disable CodeReuse/ActiveRecord -- Avoid unnecessary coupling between Project scopes and the InstanceSecurityDashboard.
  def projects
    Project.where(id: visible_users_security_dashboard_projects)
           .with_feature_available_for_user(:security_and_compliance, user)
  end
  # rubocop: enable CodeReuse/ActiveRecord

  def vulnerability_reads
    project_ids = non_archived_project_ids

    return Vulnerabilities::Read.none if project_ids.empty?

    Vulnerabilities::Read.for_projects(project_ids)
  end

  def vulnerability_scanners
    project_ids = non_archived_project_ids

    return Vulnerabilities::Scanner.none if project_ids.empty?

    Vulnerabilities::Scanner.for_projects(project_ids)
  end

  def vulnerability_historical_statistics
    project_ids = non_archived_project_ids

    return Vulnerabilities::HistoricalStatistic.none if project_ids.empty?

    Vulnerabilities::HistoricalStatistic.for_project(project_ids)
  end

  def has_projects?
    projects.count > 0
  end

  def cluster_agents
    return Clusters::Agent.none if projects.empty?

    Clusters::Agent.for_projects(projects)
  end

  private

  # rubocop: disable CodeReuse/ActiveRecord -- Tech debt to be addressed in separate issue.
  def duo_enabled_project
    projects
      .includes(:project_setting)
      .joins(:project_setting)
      .merge(ProjectSetting.duo_features_set(true))
      .first
  end
  strong_memoize_attr :duo_enabled_project

  def visible_users_security_dashboard_projects
    return users_security_dashboard_projects if Ability.allowed?(user, :read_all_resources)

    users_security_dashboard_projects.where('EXISTS(?)', project_authorizations)
  end

  def users_security_dashboard_projects
    UsersSecurityDashboardProject.select(:project_id).where(user: user)
  end

  def project_authorizations
    ProjectAuthorization
      .select(1)
      .where(users_security_dashboard_projects: { user_id: user.id })
      .where(project_authorizations: { user_id: user.id })
      .where('users_security_dashboard_projects.project_id = project_authorizations.project_id')
      .where(access_level: authorized_access_levels)
  end

  def authorized_access_levels
    Gitlab::Access.vulnerability_access_levels
  end
  # rubocop: enable CodeReuse/ActiveRecord
end
