# frozen_string_literal: true

module Ml
  class Model < ApplicationRecord
    include Presentable
    include Sortable
    include CacheMarkdownField

    EXPERIMENT_NAME_PREFIX = '[model]'

    validates :project, :default_experiment, presence: true
    validates :name,
      format: Gitlab::Regex.ml_model_name_regex,
      uniqueness: { scope: :project },
      presence: true,
      length: { maximum: 255 }

    validate :valid_default_experiment?
    validates :description,
      length: { maximum: 10_000 }

    has_one :default_experiment, class_name: 'Ml::Experiment'
    belongs_to :project
    belongs_to :user
    has_many :versions, class_name: 'Ml::ModelVersion'
    has_many :candidates, -> { without_model_version }, class_name: 'Ml::Candidate', through: :default_experiment
    has_many :metadata, class_name: 'Ml::ModelMetadata'
    has_one :latest_version, -> { latest_by_model }, class_name: 'Ml::ModelVersion', inverse_of: :model

    scope :including_latest_version, -> { includes(:latest_version) }
    # The MlModelVersion GraphQL type has `boundary: :project`, so granular-token authorization
    # reads `version.project` for every node.
    scope :including_latest_version_project, -> { includes(latest_version: :project) }
    scope :including_project, -> { includes(:project) }
    scope :including_user, -> { includes(:user) }
    scope :with_version_count, ->(project) {
      # PostgreSQL can't infer this filter from the outer ml_models.project_id one.
      # Models of any other project get a count of 0.
      version_counts = Ml::ModelVersion
                         .by_project(project)
                         .select(:model_id, 'COUNT(*) as count')
                         .group(:model_id)

      joins("LEFT OUTER JOIN (#{version_counts.to_sql}) as version_counts ON version_counts.model_id = ml_models.id")
        .select('ml_models.*, COALESCE(version_counts.count, 0) as version_count')
    }
    scope :by_name, ->(name) { where("ml_models.name LIKE ?", "%#{sanitize_sql_like(name)}%") } # rubocop:disable GitlabSecurity/SqlInjection
    scope :by_project, ->(project) { where(project_id: project.id) }
    scope :not_deleted, -> { where(deleted_on: nil) }

    cache_markdown_field :description

    def all_packages
      Packages::MlModel::Package.where(project: project, id: versions.select(:package_id))
    end

    def package_ids
      versions.where.not(package_id: nil).pluck(:package_id) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- one model's versions; callers slice the ids
    end

    def valid_default_experiment?
      return unless default_experiment

      errors.add(:default_experiment) unless default_experiment.name == self.class.prefixed_experiment(name)
      errors.add(:default_experiment) unless default_experiment.project_id == project_id
    end

    def self.by_project_id_and_id(project_id, id)
      not_deleted.find_by(project_id: project_id, id: id)
    end

    def self.by_project_id_and_name(project_id, name)
      not_deleted.find_by(project_id: project_id, name: name)
    end

    def self.prefixed_experiment(string)
      "#{EXPERIMENT_NAME_PREFIX}#{string}"
    end
  end
end
