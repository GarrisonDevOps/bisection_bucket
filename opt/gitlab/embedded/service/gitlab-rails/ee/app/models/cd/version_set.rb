# frozen_string_literal: true

module Cd
  class VersionSet < ApplicationRecord
    include Gitlab::SQL::Pattern

    self.table_name = 'cd_version_sets'

    belongs_to :application, class_name: 'Cd::Application', inverse_of: :version_sets, optional: false
    belongs_to :organization, class_name: '::Organizations::Organization', optional: false
    belongs_to :created_by, class_name: 'User', optional: true
    has_many :version_set_entries, class_name: 'Cd::VersionSetEntry', inverse_of: :version_set
    has_many :versions, through: :version_set_entries
    has_many :rollouts, class_name: 'Cd::Rollout', inverse_of: :version_set
    has_many :rollout_environments, class_name: 'Cd::RolloutEnvironment', inverse_of: :previous_version_set,
      foreign_key: :previous_version_set_id

    populate_sharding_key :organization_id, source: :application

    # Release (version set) lifecycle statuses exposed via the GraphQL API.
    # See `.statuses_by_id` for how each is derived.
    NON_TERMINAL_ROLLOUT_STATES = %w[pending in_progress paused].freeze

    scope :in_organization, ->(organization) { where(organization_id: organization) }
    scope :search, ->(query) { fuzzy_search(query, [:name, :description]) }

    # Restricts the relation to version sets whose derived `#status` is one of
    # the given statuses. Unknown statuses simply match nothing, rather than
    # raising or matching every version set.
    #
    # Computes the status for every version set in the relation (bounded to a
    # single application's release list, same assumption `Cd::Rollout.for_statuses`
    # relies on), so this is best used on an already narrowly-scoped relation.
    scope :for_statuses, ->(statuses) {
      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded to a single application's release list
      matching_ids = statuses_by_id(pluck(:id)).select { |_id, status| statuses.include?(status) }.keys
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit

      where(id: matching_ids)
    }

    validates :name, presence: true, length: { maximum: 255 }, uniqueness: { scope: :application_id }
    validates :description, length: { maximum: 2000 }
    validates :entries_digest, uniqueness: { scope: :application_id }, allow_nil: true

    # High-level lifecycle status for each of the given version set ids, keyed
    # by id. Version sets with no special status (currently live and never
    # replaced, or with no rollouts yet, or whose latest rollout failed or was
    # cancelled) are omitted, so callers can distinguish "no status" from an
    # observed one.
    #
    # See `#status` for the per-record derivation this batches.
    def self.statuses_by_id(version_set_ids)
      where(id: version_set_ids)
        .includes(rollouts: { rollout_environments: :previous_version_set }, rollout_environments: :rollout)
        .each_with_object({}) do |version_set, result|
          status = version_set.status
          result[version_set.id] = status if status
        end
    end

    # Derives this release's high-level lifecycle status from its rollout
    # history:
    #
    # - "deploying": the latest rollout hasn't reached a terminal state yet.
    # - "rolled_back": the latest (completed) rollout redeployed this version
    #   set to an environment that, at the time, was running a newer release
    #   (i.e. this rollout moved that environment backward).
    # - "superseded": this version set has since been replaced, in at least
    #   one environment, by another release's completed rollout.
    # - nil: none of the above (the release is current/live, has no rollouts
    #   yet, or its latest rollout failed/was cancelled).
    def status
      latest_rollout = rollouts.max_by { |rollout| [rollout.created_at, rollout.id] }

      return unless latest_rollout

      if NON_TERMINAL_ROLLOUT_STATES.include?(latest_rollout.state)
        'deploying'
      elsif latest_rollout.completed?
        if rolled_back?(latest_rollout)
          'rolled_back'
        elsif superseded?
          'superseded'
        end
      end
    end

    def compute_entries_digest
      fingerprints = version_set_entries.order(:artifact_source_id).map do |entry|
        "#{entry.artifact_source_id}:#{entry.version_id}"
      end

      return if fingerprints.empty?

      Digest::SHA256.hexdigest(fingerprints.join(','))
    end

    def update_entries_digest!
      update_column(:entries_digest, compute_entries_digest)
    end

    private

    # True when `rollout` (this version set's latest rollout) redeployed at
    # least one environment that, immediately before, was running a release
    # newer than this one.
    def rolled_back?(rollout)
      rollout.rollout_environments.any? do |rollout_environment|
        previous = rollout_environment.previous_version_set

        previous && self.class.newer?(previous, self)
      end
    end

    # True when at least one environment this version set was deployed to has
    # since been completed over by a *different* release (redeploying the
    # same release again, e.g. to pick up an unrelated config change, does
    # not count as superseding itself).
    def superseded?
      rollout_environments.any? do |rollout_environment|
        rollout_environment.rollout.completed? && rollout_environment.rollout.version_set_id != id
      end
    end

    class << self
      # True when `candidate` was created more recently than `reference`
      # (ties broken by id), i.e. `candidate` is a newer release.
      def newer?(candidate, reference)
        return false if candidate.id == reference.id

        ([candidate.created_at, candidate.id] <=> [reference.created_at, reference.id]) == 1
      end
    end
  end
end
