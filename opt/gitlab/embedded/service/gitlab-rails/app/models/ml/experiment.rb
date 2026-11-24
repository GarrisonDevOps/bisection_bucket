# frozen_string_literal: true

module Ml
  class Experiment < ApplicationRecord
    include AtomicInternalId
    include Sortable
    include Presentable

    PACKAGE_PREFIX = 'ml_experiment_'
    DELETION_SCHEDULED_PREFIX = 'deletion_scheduled-'
    MODEL_EXPERIMENT_DELETION_ERROR = 'Cannot delete an experiment associated to a model'

    validates :name, :project, presence: true
    validates :name, uniqueness: { scope: :project, message: "should be unique in the project" }

    belongs_to :project
    belongs_to :user
    belongs_to :model, optional: true, inverse_of: :default_experiment
    has_many :candidates, class_name: 'Ml::Candidate'
    has_many :metadata, class_name: 'Ml::ExperimentMetadata'

    scope :including_project, -> { includes(:project) }
    scope :including_user, -> { includes(:user) }
    scope :including_metadata, -> { preload(:metadata) }
    scope :by_project, ->(project) { where(project: project) }
    scope :with_candidate_count, -> {
      left_outer_joins(:candidates)
        .select("ml_experiments.*, count(ml_candidates.id) as candidate_count")
        .group(:id)
    }
    scope :exclude_experiments_for_models, -> { where(model_id: nil) }
    scope :not_deleted, -> { where(deleted_on: nil) }
    # Ml::DestroyExperimentWorker moves deleted_on into the future while it works on an experiment.
    scope :ready_for_deletion, -> { where(deleted_on: ..Time.current) }

    has_internal_id :iid, scope: :project

    before_destroy :stop_destroy

    def package_name
      return model.name if for_model?

      "#{PACKAGE_PREFIX}#{iid}"
    end

    def for_model?
      model.present?
    end

    def more_candidates_than?(count)
      candidates.offset(count).exists?
    end

    def stop_destroy
      return unless model_id

      errors.add(:base, MODEL_EXPERIMENT_DELETION_ERROR)
      # According to docs, throw is the correct way to stop on a callback
      # https://api.rubyonrails.org/classes/ActiveRecord/Callbacks.html#module-ActiveRecord::Callbacks-label-Canceling+callbacks
      throw :abort # rubocop:disable Cop/BanCatchThrow
    end

    # Hides the experiment and frees its name; Ml::DestroyExperimentWorker deletes it.
    def mark_for_deletion
      if model_id
        errors.add(:base, MODEL_EXPERIMENT_DELETION_ERROR)
        return false
      end

      assign_deletion_attributes
      save
    end

    # The random suffix keeps the new name from matching a name that a user can pick.
    def assign_deletion_attributes
      assign_attributes(deleted_on: Time.current, name: "#{DELETION_SCHEDULED_PREFIX}#{id}-#{SecureRandom.hex(8)}")
    end

    class << self
      def by_project_id_and_iid(project_id, iid)
        not_deleted.find_by(project_id: project_id, iid: iid)
      end

      def by_project_id_and_name(project_id, name)
        not_deleted.find_by(project_id: project_id, name: name)
      end

      def next_ready_for_deletion
        ready_for_deletion.order(:deleted_on, :id).lock('FOR UPDATE SKIP LOCKED').first
      end

      def package_for_experiment?(package_name)
        return false unless package_name&.starts_with?(PACKAGE_PREFIX)

        iid = package_name.delete_prefix(PACKAGE_PREFIX)

        numeric?(iid)
      end

      def find_or_create(project, name, user)
        create_with(user: user).find_or_create_by(project: project, name: name)
      end

      private

      def numeric?(value)
        value.match?(/\A\d+\z/)
      end
    end
  end
end
