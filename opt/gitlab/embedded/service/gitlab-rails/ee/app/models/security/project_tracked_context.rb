# frozen_string_literal: true

# security_project_tracked_contexts exists to track contexts related to a project to which
# vulnerability information may related and or actively tracked from. In the initial scope
# this is limited to git refs in the traditional static analysis sense, but will likely expand to
# accomodate contexts like job artifacts, logs, packages, containers and more
#
# A record existing in this table does not directly imply tracking, only that the context exists
# and may have vulnerability information related to it. For tracking to be actively enabled against
# that context, the `tracking` field should be set to true

module Security
  class ProjectTrackedContext < ::SecApplicationRecord
    include SafelyChangeColumnDefault
    include ::Gitlab::Utils::StrongMemoize

    self.table_name = 'security_project_tracked_contexts'

    columns_changing_default :is_default

    STATES = { untracked: 1, tracked: 2, archiving: 0, deleting: -1 }.freeze

    # Older vulnerability data uses UUIDs that do not consider the tracked context. This data only
    # exists on the default branch. We describe those as "version 1 vulnerability UUIDs".
    # When we enabled multiple branch tracking we wanted all UUIDs on non-default branches and
    # UUIDs on *newly created default branches* to consider the tracked context. Those are
    # "version 2 vulnerability UUIDs". For consistency and safety, we use the `uuid_version` field
    # set on the tracked context for that ref to be the discriminator between which UUID mechanism
    # to use.
    CONTEXT_UNAWARE_UUID_VERSION = 1
    CONTEXT_AWARE_UUID_VERSION = 2

    belongs_to :project, inverse_of: :security_project_tracked_contexts

    has_many :sbom_occurrence_refs,
      class_name: 'Sbom::OccurrenceRef',
      foreign_key: 'security_project_tracked_context_id',
      inverse_of: :tracked_context
    has_many :vulnerability_reads,
      class_name: 'Vulnerabilities::Read',
      foreign_key: 'security_project_tracked_context_id',
      inverse_of: :tracked_context

    validates :context_name, presence: true, length: { maximum: 1024 }
    validates :context_type, presence: true
    validates :context_name, uniqueness: { scope: [:project_id, :context_type] }
    validate :tracked_refs_limit
    validate :organization_quota_not_exceeded, if: :transitioning_to_tracked?
    validate :default_ref_cannot_be_untracked, if: :is_default?
    validate :only_branch_refs_can_be_default, if: :is_default?

    before_create :set_traversal_ids

    enum :context_type, {
      branch: 1,
      tag: 2
    }

    state_machine :state, initial: :untracked do
      STATES.each do |state_name, value|
        state state_name, value: value
      end

      event :untrack do
        transition tracked: :untracked
      end

      event :track do
        transition untracked: :tracked
      end

      event :archive do
        transition [:untracked, :tracked] => :archiving
      end

      event :remove do
        transition any => :deleting
      end
    end

    scope :for_project, ->(project_id) { where(project: project_id) }
    scope :default_refs, -> { where(is_default: true) }
    scope :non_default_refs, -> { where(is_default: false) }
    scope :for_context_name, ->(context_name) { where(context_name: context_name) }
    scope :for_context_type, ->(context_type) { where(context_type: context_type) }
    scope :default_branch, -> { for_context_type(:branch).default_refs }
    scope :code_refs, -> { for_context_type([:branch, :tag]) }
    scope :for_ref, ->(ref_name) { for_context_name(ref_name).code_refs }
    scope :with_traversal_ids_other_than, ->(traversal_ids) { where.not(traversal_ids: traversal_ids) }

    scope :for_pipeline, ->(pipeline) do
      context_type = pipeline.tag? ? :tag : :branch

      where(
        project: pipeline.project,
        context_name: pipeline.tracked_context_ref,
        context_type: context_type
      )
    end

    # Scopes records to the given root namespace ids using the denormalized
    # `traversal_ids` column. Used for organization-scoped counting without
    # cross-database joins, since this table lives on the `sec` database.
    #
    # Each root namespace is matched with a half-open range on the whole
    # `traversal_ids` array (`traversal_ids >= '{id}' AND traversal_ids < '{id + 1}'`),
    # mirroring `Namespaces::Traversal::Traversable#within`. This lets the query
    # use the btree index on `traversal_ids` instead of an unindexable
    # `traversal_ids[1]` element-subscript predicate (which forces a sequential
    # scan). The array-literal bounds are built as quoted Arel values rather than
    # interpolated into a SQL string, so there is no raw-string injection surface.
    scope :for_root_namespaces, ->(root_namespace_ids) do
      validated_ids = Array(root_namespace_ids).map { |id| Integer(id) }
      next if validated_ids.empty?

      column = arel_table[:traversal_ids]
      ranges = validated_ids.map do |id|
        column.gteq(Arel::Nodes.build_quoted("{#{id}}"))
          .and(column.lt(Arel::Nodes.build_quoted("{#{id + 1}}")))
      end

      where(ranges.reduce(:or))
    end

    STATES.each do |state_name, value|
      scope state_name, -> { where(state: value) }
    end

    # Maximum number of tracked refs per project (default branch + 3 additional refs)
    MAX_TRACKED_REFS_PER_PROJECT = 4
    # Increased limit for projects with vac_increased_limit feature flag enabled
    MAX_TRACKED_REFS_INCREASED = 1000

    def self.tracked_pipeline?(pipeline)
      for_pipeline(pipeline).tracked.exists?
    end

    def self.find_default_branch_context(project)
      find_by(
        project: project,
        context_name: project.default_branch_or_main,
        context_type: :branch
      )
    end

    # Returns default branch tracked contexts for the given projects, indexed by `project_id`.
    # Performs a single query using a `(project_id, context_name) IN (VALUES ...)` clause to
    # avoid N+1 queries when looking up multiple projects' default branch contexts.
    def self.default_branch_contexts_by_project_id(projects)
      projects = Array.wrap(projects)
      return {} if projects.empty?

      tuples = projects.map { |p| [p.id, p.default_branch_or_main] }
      table = arel_table

      branch.where(
        Arel::Nodes::In.new(
          Arel::Nodes::Grouping.new([table[:project_id], table[:context_name]]),
          Arel::Nodes::ValuesList.new(tuples)
        )
      ).index_by(&:project_id)
    end

    def ref_exists_in_repository?
      return false unless project&.repository_exists?

      case context_type.to_sym
      when :branch
        project.repository.branch_exists?(context_name)
      when :tag
        project.repository.tag_exists?(context_name)
      else
        false
      end
    end
    strong_memoize_attr :ref_exists_in_repository?

    def protected?
      return false unless ref_exists_in_repository?

      case context_type.to_sym
      when :branch
        project.protected_branches.matching(context_name).any?
      when :tag
        project.protected_tags.matching(context_name).any?
      else
        false
      end
    end

    def commit
      return unless ref_exists_in_repository?

      qualified_ref = case context_type.to_sym
                      when :branch then "#{Gitlab::Git::BRANCH_REF_PREFIX}#{context_name}"
                      when :tag then "#{Gitlab::Git::TAG_REF_PREFIX}#{context_name}"
                      end

      return unless qualified_ref

      project.repository.commit(qualified_ref)
    rescue Gitlab::Git::Repository::NoRepository, Gitlab::Git::ReferenceNotFoundError, Rugged::ReferenceError => e
      Gitlab::ErrorTracking.track_exception(e, project_id: project.id, ref_name: context_name)
      nil
    end

    def context_aware_uuids_enabled?
      return true if uuid_version == CONTEXT_AWARE_UUID_VERSION
      return true if uuid_version == CONTEXT_UNAWARE_UUID_VERSION && !is_default?

      false
    end

    private

    def set_traversal_ids
      self.traversal_ids = project.namespace.traversal_ids if traversal_ids.blank?
    end

    def tracked_refs_limit
      return unless tracked?
      # The per-project ref cap is superseded by the organization-level quota
      # once quota enforcement is active for the project. When enforcement is
      # on, org quota is the single source of truth for how many contexts can
      # be tracked (see organization_quota_not_exceeded); the per-project cap
      # only applies while enforcement is off.
      return if organization_quota_enforced?

      tracked_query = self.class.for_project(project_id).tracked
      tracked_query = tracked_query.where.not(id: id) if persisted?

      return unless tracked_query.limit(max_tracked_refs_for_project).count >= max_tracked_refs_for_project

      errors.add(:base, "cannot exceed #{max_tracked_refs_for_project} tracked refs per project")
    end

    def max_tracked_refs_for_project
      @max_tracked_refs_for_project ||= self.class.max_tracked_refs_for_project(project)
    end

    class << self
      def max_tracked_refs_for_project(project)
        return MAX_TRACKED_REFS_INCREASED if Feature.enabled?(:vac_increased_limit, project)

        MAX_TRACKED_REFS_PER_PROJECT
      end
    end

    def transitioning_to_tracked?
      tracked? && (new_record? || state_changed?)
    end

    def organization_quota_not_exceeded
      organization = project&.organization
      return unless organization

      # rubocop:disable CodeReuse/ServiceClass -- quota logic is centralised in the service and shared with the API/UI; duplicating it in the model would risk divergence
      quota_service = Security::TrackedContextQuotaService.new(organization)
      # rubocop:enable CodeReuse/ServiceClass
      # The project is the VAC enablement actor (VAC is gated per-project during
      # the closed-beta rollout).
      return if quota_service.quota_available?(project)

      errors.add(:base, quota_service.quota_exceeded_error_message)
    end

    # Whether the organization-level quota is being enforced for this project.
    # When true, the org quota replaces the per-project tracked-refs cap. Reuses
    # the service's flag gate so the model and service stay in lockstep.
    def organization_quota_enforced?
      organization = project&.organization
      return false unless organization

      # rubocop:disable CodeReuse/ServiceClass -- reuse the service's enforcement gate so model and service can't diverge
      Security::TrackedContextQuotaService.new(organization).quota_enforcement_enabled?(project)
      # rubocop:enable CodeReuse/ServiceClass
    end

    def default_ref_cannot_be_untracked
      return if tracked?

      errors.add(:base, 'default ref must be tracked')
    end

    def only_branch_refs_can_be_default
      return if branch?

      errors.add(:base, 'only branch refs can be default')
    end
  end
end
