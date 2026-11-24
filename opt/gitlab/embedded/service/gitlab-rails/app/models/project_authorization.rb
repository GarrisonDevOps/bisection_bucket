# frozen_string_literal: true

class ProjectAuthorization < ApplicationRecord
  include FromUnion
  include SafelyChangeColumnDefault

  belongs_to :user
  belongs_to :project

  validates :project, presence: true
  validates :access_level, inclusion: { in: Gitlab::Access.all_values }, presence: true
  validates :user, uniqueness: { scope: :project }, presence: true

  # Column shape required by .access_levels_by_project
  EXPECTED_PAIR_COLUMNS = %w[project_id access_level].freeze

  scope :for_project, ->(projects) { where(project: projects) }
  scope :for_user, ->(user_ids) { where(user_id: user_ids) }
  scope :non_guests, -> { where('access_level > ?', ::Gitlab::Access::GUEST) }
  scope :owners, -> { where(access_level: ::Gitlab::Access::OWNER) }

  scope :for_project_groups, ->(user_ids, organization: nil) do
    lateral_query = Project
      .joins(:namespace)
      .where('projects.id = project_authorizations.project_id')
      .where(namespaces: { type: Group.sti_name })
      .select('namespaces.id')
      .limit(1)

    lateral_query = lateral_query.where(namespaces: { organization_id: organization }) if organization

    for_user(user_ids)
      .joins("CROSS JOIN LATERAL (#{lateral_query.to_sql}) g")
      .select('g.id, project_authorizations.user_id as user_id')
  end

  scope :preload_users, -> { preload(:user) }

  scope :count_by_user_id, -> do
    group(:user_id).count
  end

  # columns_changing_default forces is_unique into every INSERT while the database default
  # is in flux, so a process holding a stale schema cache cannot fall back to a default it
  # cannot see. It is removed in the release after the default ships.
  # TODO: To be removed after https://gitlab.com/gitlab-org/gitlab/-/issues/418205
  before_create :assign_is_unique
  columns_changing_default :is_unique

  # Reads authorizations as raw [project_id, access_level] pairs. A single user
  # can be authorized on tens of thousands of projects, and instantiating one
  # record per row dominates the cost of an authorization refresh - most of
  # which find nothing to change.
  #
  # The result is deliberately unbounded. It is diffed in memory against the
  # freshly calculated set and never fed into an IN clause, and a limit here
  # would be unsafe: rows past the cut-off would never be compared, so
  # revocations for them would be silently skipped. At the largest sizes seen in
  # production - roughly 47k projects for one user - these pairs occupy about
  # 2 MB, against about 18 MB for the ActiveRecord objects they replace.
  def self.project_ids_and_access_levels_for(user_id)
    for_user(user_id).pluck(:project_id, :access_level) # rubocop: disable Database/AvoidUsingPluckWithoutLimit -- see above
  end

  # The stored levels of one user on the given projects. Lists, because legacy duplicate rows can hold
  # several levels for one pair.
  #
  # @return [Hash{Integer => Array<Integer>}] keyed by project ID, only for projects with rows
  def self.stored_levels_for_user(user_id, project_ids)
    where(user_id: user_id, project_id: project_ids)
      .pluck(:project_id, :access_level) # rubocop: disable Database/AvoidUsingPluckWithoutLimit -- bounded by the project IDs
      .group_by(&:first).transform_values { |pairs| pairs.map(&:last) }
  end

  # The stored levels on one project, for the given users or every user.
  #
  # @return [Hash{Integer => Array<Integer>}] keyed by user ID, only for users with rows
  def self.stored_levels_for_project(project_id, user_ids = nil)
    scope = where(project_id: project_id)
    scope = scope.where(user_id: user_ids) if user_ids

    scope.pluck(:user_id, :access_level) # rubocop: disable Database/AvoidUsingPluckWithoutLimit -- one project's rows, as a project recalculation reads them
      .group_by(&:first).transform_values { |pairs| pairs.map(&:last) }
  end

  # Deletes one user's rows on the given projects, legacy duplicates included.
  #
  # @return [Integer] the number of rows deleted
  def self.delete_for_user(user_id, project_ids)
    where(user_id: user_id, project_id: project_ids).delete_all
  end

  # Deletes the given users' rows on one project, legacy duplicates included.
  #
  # @return [Integer] the number of rows deleted
  def self.delete_for_project(project_id, user_ids)
    where(project_id: project_id, user_id: user_ids).delete_all
  end

  # Of the given projects, those whose members may still be waiting on the project's
  # own refresh: projects created since `since`, and projects with an import in progress.
  def self.project_ids_pending_own_refresh(project_ids, since:)
    limit = project_ids.size

    # Imports in progress are few, so start from the import state rather than the projects
    importing = ProjectImportState.where(project_id: project_ids).with_status(:scheduled, :started)

    Project.id_in(project_ids).where(created_at: since..).limit(limit).pluck(:id) |
      importing.limit(limit).pluck(:project_id)
  end

  # Of the given projects, those that no longer exist. Loose-foreign-key cleanup removes
  # their authorizations, so a refresh does not need to.
  def self.deleted_project_ids(project_ids)
    project_ids - Project.id_in(project_ids).limit(project_ids.size).pluck(:id)
  end

  # As above, for an already-built relation such as a freshly calculated set.
  #
  # `pluck` is not an option here, unlike in the method above. The relation this
  # receives aggregates, as
  # `SELECT project_id, MAX(access_level) AS access_level ... GROUP BY project_id`,
  # and `pluck` replaces the select list, which would leave `access_level`
  # outside an aggregate for Postgres to reject.
  #
  # The relation must select exactly project_id then access_level: the result is
  # mapped to a Hash by column position, so a different shape would silently
  # produce wrong access levels rather than fail. Checked once per call.
  def self.access_levels_by_project(relation)
    result = connection.select_all(relation.to_sql)

    unless result.columns == EXPECTED_PAIR_COLUMNS
      raise ArgumentError,
        "expected #{EXPECTED_PAIR_COLUMNS.join(', ')}; got #{result.columns.join(', ')}"
    end

    result.cast_values.to_h
  end

  # Of the given projects, those archived themselves or through an archived ancestor group.
  #
  # @param project_ids [Array<Integer>]
  # @return [Array<Integer>]
  def self.archived_project_ids(project_ids)
    Project.id_in(project_ids).self_or_ancestors_archived.limit(project_ids.size).pluck(:id)
  end

  def self.select_from_union(relations)
    from_union(relations)
      .select(['project_id', 'MAX(access_level) AS access_level'])
      .group(:project_id)
  end

  # Postgres only skips conflicts on the index named in ON CONFLICT, this table has three unique indexes,
  # and Rails' insert_all always names one, so the statement is written here without a target.
  # Replace with upsert_all after https://gitlab.com/gitlab-org/gitlab/-/work_items/635982
  def self.insert_all(attributes)
    return ActiveRecord::Result.empty if attributes.empty?

    keys = attributes.first.keys
    raise ArgumentError, 'All rows must have the same keys' unless attributes.all? { |row| row.keys == keys }

    columns = keys.map { |key| connection.quote_column_name(key) }.join(',')
    values = attributes.map { |row| "(#{row.values_at(*keys).map { |value| connection.quote(value) }.join(',')})" }

    # exec_insert_all, unlike exec_query, makes the load balancer stick the session to the primary
    connection.exec_insert_all(
      "INSERT INTO #{quoted_table_name} (#{columns}) VALUES #{values.join(',')} " \
        'ON CONFLICT DO NOTHING RETURNING "user_id","project_id","access_level"',
      "#{name} Insert"
    )
  end

  def self.find_or_create_authorization_for(user_id, project_id, access_level)
    # We only try to find the record by user and project so that we match the current model level validation and
    # database constraints.
    # Ideally, in the case where a record exists with a different access_level,
    # this will save us from performing an unnecessary upsert that will hit the `ON CONFLICT DO NOTHING` path.
    # Due to the nature of project authorizations, differences in access_level should be handled by the
    # recalculation service/workers and not anything that invokes this method.
    find_by(user_id: user_id, project_id: project_id) ||

      # If not, we try to create it with `upsert`.
      # We use upsert for these reasons:
      #    - No subtransactions
      #    - Due to the use of `on_duplicate: :skip`, we are essentially issuing a `ON CONFLICT DO NOTHING`.
      #       - Postgres will take care of skipping the record without errors if a similar record was created
      #         by then in another thread.
      #       - There is no explicit error being thrown because we said "ON CONFLICT DO NOTHING".
      #         With this we avoid both the problems with subtransactions that could arise when we upgrade Rails,
      #         see https://gitlab.com/gitlab-org/gitlab/-/issues/439567, and also with race conditions.

      upsert(
        { project_id: project_id, user_id: user_id, access_level: access_level, is_unique: true },
        unique_by: [:project_id, :user_id], # skip unique_by access_level here to avoid conflicting access.
        on_duplicate: :skip # Do not change access_level, could cause conflicting permissions.
      )
  end

  private

  def assign_is_unique
    self.is_unique = true
  end
end

ProjectAuthorization.prepend_mod_with('ProjectAuthorization')
