# frozen_string_literal: true

# This model represents a merge train with many Merge Request 'Cars' for a projects branch
module MergeTrains
  class Train
    include Gitlab::Utils::StrongMemoize

    MERGE_REQUEST_REFRESH_PRELOADS = [
      :source_project, :target_project, :latest_merge_request_diff, :running_scan_result_policy_violations
    ].freeze

    STATUSES = {
      active: 'active',
      completed: 'completed'
    }.freeze

    def self.all_for_project(project)
      MergeTrains::Car
      .active
      .where(target_project: project)
      .select('DISTINCT ON (target_branch) *')
      .map(&:train)
    end

    # Consider moving to finder
    def self.all_for(project, status: nil, target_branch: [])
      cars = MergeTrains::Car
                 .where(target_project: project)
      cars = cars.where(target_branch: target_branch) if target_branch.present?

      case status
      when :completed, STATUSES[:completed]
        cars = cars.where.not(target_branch: cars.active.select(:target_branch))
      when :active, STATUSES[:active]
        cars = cars.active
      end

      cars
        .select('DISTINCT ON (merge_trains.target_branch) *')
        .map(&:train)
    end

    def self.project_using_ff?(project)
      project.merge_trains_enabled? &&
        project.ff_merge_must_be_possible?
    end

    attr_reader :project_id, :target_branch

    def initialize(project_id, branch)
      @project_id = project_id
      @target_branch = branch
    end

    def project
      Project.find_by_id(project_id)
    end
    strong_memoize_attr :project

    def refresh_async
      MergeTrains::RefreshWorker.perform_async(project_id, target_branch)
    end

    def first_active_car
      all_active_cars.first
    end

    def car_count
      all_active_cars.count
    end

    def active?
      all_active_cars.any?
    end

    def completed?
      !active?
    end

    def sha_exists_in_history?(newrev, limit: 20)
      MergeRequest.where(id: completed_cars(limit: limit).select(:merge_request_id))
        .where(
          'merge_commit_sha = ? OR in_progress_merge_commit_sha = ? OR squash_commit_sha = ? OR merged_commit_sha = ?',
          newrev, newrev, newrev, newrev)
        .exists?
    end

    def all_active_cars(limit: nil)
      persisted_cars.active.by_id.limit(limit)
    end

    def all_active_cars_indexed(limit: nil)
      all_active_cars(limit: limit).indexed
    end

    def completed_cars(limit: nil)
      persisted_cars.complete.by_id(:desc).limit(limit)
    end

    # Loaded eagerly: otherwise each car resolves its own project, user, merge
    # request, pipeline and diff, so a refresh scales with the length of the train.
    def refreshable_cars(limit: nil)
      cars = persisted_cars.refreshable.by_id.limit(limit)

      # Pipelines must be preloaded through the relation, which is extended with
      # the partition-aware preloader. Moving them into the Preloader call below
      # loses partition pruning on p_ci_pipelines.
      cars.preload(:pipeline).to_a.tap { |records| preload_refresh_associations(records) }
    end

    private

    # Every car on a train targets the same project, so hand the already-loaded
    # one to the preloader rather than reloading the row per association.
    def preload_refresh_associations(cars)
      ActiveRecord::Associations::Preloader.new(
        records: cars,
        associations: [:user, :target_project, { merge_request: MERGE_REQUEST_REFRESH_PRELOADS }],
        available_records: [project].compact
      ).call
    end

    def persisted_cars
      MergeTrains::Car.for_target(project_id, target_branch).with_partition_aware_preload
    end
  end
end
