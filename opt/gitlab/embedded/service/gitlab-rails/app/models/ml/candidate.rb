# frozen_string_literal: true

module Ml
  class Candidate < ApplicationRecord
    include Sortable
    include Presentable
    include AtomicInternalId

    enum :status, { running: 0, scheduled: 1, finished: 2, failed: 3, killed: 4 }

    PACKAGE_PREFIX = 'candidate_'

    validates :eid, :experiment, :project, presence: true
    validates :status, inclusion: { in: statuses.keys }
    validates :model_version_id, uniqueness: { allow_nil: true }

    belongs_to :experiment, class_name: 'Ml::Experiment'
    belongs_to :user
    belongs_to :package, class_name: 'Packages::Package'
    belongs_to :project
    belongs_to :ci_build, class_name: 'Ci::Build', optional: true
    belongs_to :model_version, class_name: 'Ml::ModelVersion', optional: true, inverse_of: :candidate
    has_many :metrics, class_name: 'Ml::CandidateMetric'
    has_many :params, class_name: 'Ml::CandidateParam'
    has_many :metadata, class_name: 'Ml::CandidateMetadata'
    has_many :latest_metrics, -> { latest }, class_name: 'Ml::CandidateMetric', inverse_of: :candidate

    attribute :eid, default: -> { SecureRandom.uuid }

    has_internal_id :internal_id,
      scope: :project,
      init: AtomicInternalId.project_init(self, :internal_id)

    before_destroy :check_model_version

    scope :including_relationships, -> { includes(:latest_metrics, :params, :user, :package, :project, :ci_build) }
    scope :including_metadata, -> { preload(:metadata) }
    scope :including_ci_build_user_and_project, -> { preload(ci_build: [:user, :project]) }
    scope :by_name, ->(name) { where("ml_candidates.name LIKE ?", "%#{sanitize_sql_like(name)}%") } # rubocop:disable GitlabSecurity/SqlInjection
    scope :without_model_version, -> { where(model_version: nil) }
    scope :for_model_version_ids, ->(ids) { where(model_version_id: ids) }

    scope :order_by_metric, ->(metric, direction, lateral: false) do
      latest_metric_join =
        if lateral
          # The ON clause names `latest` so that `includes` keeps preloading associations instead of eager loading them.
          subquery = Ml::CandidateMetric.select(:candidate_id, :value).where(name: metric)
            .where(Ml::CandidateMetric.arel_table[:candidate_id].eq(arel_table[:id]))
            .order(id: :desc).limit(1)
          "INNER JOIN LATERAL (#{subquery.to_sql}) latest ON latest.candidate_id = ml_candidates.id"
        else
          subquery = Ml::CandidateMetric.latest.where(name: metric)
          "INNER JOIN (#{subquery.to_sql}) latest ON latest.candidate_id = ml_candidates.id"
        end

      column_expression = Arel::Table.new('latest')[:value]
      metric_order_expression = direction.to_sym == :desc ? column_expression.desc : column_expression.asc

      joins(latest_metric_join)
        .select("ml_candidates.*", "latest.value as metric_value")
        .order(
          Gitlab::Pagination::Keyset::Order.build(
            [
              Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
                attribute_name: 'metric_value',
                column_expression: column_expression,
                order_expression: metric_order_expression.nulls_last,
                nullable: :nulls_last
              ),
              Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
                attribute_name: 'id',
                order_expression: arel_table[:id].desc
              )
            ])
        )
    end

    scope :without_preloads, -> { unscope(:includes, :preload) }

    alias_method :artifact, :package
    alias_method :artifact=, :package=

    alias_attribute :iid, :internal_id
    alias_method :iid=, :internal_id=

    delegate :package_name, to: :experiment

    def artifact_root
      "/#{package_name}/#{package_version}/"
    end

    def package_version
      package&.generic? ? iid : "#{PACKAGE_PREFIX}#{iid}"
    end

    def from_ci?
      ci_build_id.present?
    end

    def for_model?
      experiment.for_model? && !model_version_id.present?
    end

    class << self
      def with_project_id_and_eid(project_id, eid)
        return unless project_id.present? && eid.present?

        unless_experiment_deleted(find_by(project_id: project_id, eid: eid))
      end

      def with_project_id_and_iid(project_id, iid)
        return unless project_id.present? && iid.present?

        unless_experiment_deleted(find_by(project_id: project_id, internal_id: iid))
      end

      def with_project_id_and_id(project_id, id)
        return unless project_id.present? && id.present?

        unless_experiment_deleted(find_by(project_id: project_id, id: id))
      end

      private

      # Runs of an experiment marked for deletion stay until Ml::DestroyExperimentWorker removes them.
      def unless_experiment_deleted(candidate)
        return candidate unless candidate && delete_experiments_in_batches?(candidate.project_id)

        candidate unless candidate.experiment.deleted_on?
      end

      def delete_experiments_in_batches?(project_id)
        Feature.enabled?(:ml_delete_experiments_in_batches, Project.actor_from_id(project_id))
      end
    end

    private

    def check_model_version
      return unless model_version_id

      errors.add(:base, _("Cannot delete a candidate associated to a model version"))
      throw :abort # rubocop:disable Cop/BanCatchThrow
    end
  end
end
