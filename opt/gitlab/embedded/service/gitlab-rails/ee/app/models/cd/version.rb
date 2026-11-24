# frozen_string_literal: true

module Cd
  class Version < ApplicationRecord
    self.table_name = 'cd_versions'

    belongs_to :artifact_source, class_name: 'Cd::ArtifactSource', inverse_of: :versions, optional: false
    belongs_to :organization, class_name: '::Organizations::Organization', optional: false
    has_many :version_set_entries, class_name: 'Cd::VersionSetEntry', inverse_of: :version

    populate_sharding_key :organization_id, source: :artifact_source

    scope :for_application, ->(application) {
      joins(artifact_source: :service).where(cd_services: { application_id: application })
    }
    scope :for_artifact_sources, ->(artifact_sources) { where(artifact_source_id: artifact_sources) }
    scope :with_name, ->(name) { where(name: name) }
    scope :preload_artifact_source_and_service, -> { preload(artifact_source: :service) }

    validates :name, presence: true, length: { maximum: 255 }, uniqueness: { scope: :artifact_source_id }
    validates :name, format: {
      with: Gitlab::Regex.cd_version_name_regex, message: Gitlab::Regex.cd_version_name_regex_message
    }, if: :verified?
    validates :digest, length: { maximum: 255 }
    validates :reference, length: { maximum: 1024 }

    # Batched form of #environments for a list of versions, so that resolving
    # `environments` for a page of versions (for example, in GraphQL) executes
    # a small, fixed number of queries -- one per distinct service among the
    # given versions -- rather than one query per version.
    #
    # Returns a Hash of version id => Array of Cd::Environment.
    def self.environments_for(versions)
      versions = Array(versions)
      return {} if versions.empty?

      version_set_ids_by_version_id = version_set_ids_by_version_id(versions)

      versions.group_by { |version| version.artifact_source.service_id }
        .each_with_object({}) do |(service_id, service_versions), result|
          environments_for_service_versions(service_id, service_versions, version_set_ids_by_version_id, result)
        end
    end

    def self.version_set_ids_by_version_id(versions)
      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by the caller's page size
      ::Cd::VersionSetEntry
        .where(version_id: versions.map(&:id))
        .pluck(:version_id, :version_set_id)
        .group_by(&:first)
        .transform_values { |rows| rows.map(&:second) }
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit
    end

    def self.environments_for_service_versions(service_id, service_versions, version_set_ids_by_version_id, result)
      version_set_ids = service_versions.flat_map { |version| version_set_ids_by_version_id[version.id] || [] }.uniq
      rows = version_set_ids.empty? ? [] : environments_for_service(service_id, version_set_ids)
      rows_by_version_set_id = rows.group_by(&:matched_version_set_id)

      service_versions.each do |version|
        own_version_set_ids = version_set_ids_by_version_id[version.id] || []
        result[version.id] = own_version_set_ids
          .flat_map { |version_set_id| rows_by_version_set_id[version_set_id] || [] }
          .uniq(&:id)
      end
    end

    def self.environments_for_service(service_id, version_set_ids)
      ::Cd::Environment
        .joins(rollout_environments: [:deployments, { rollout: :version_set }])
        .where(cd_version_sets: { id: version_set_ids })
        .where(cd_deployments: { service_id: service_id })
        .select('cd_environments.*', 'cd_version_sets.id AS matched_version_set_id')
    end

    # Batched inverse of #environments: the version(s) of a service currently
    # deployed in each of the given (service, environment) pairs, in a fixed
    # number of queries regardless of how many services or environments are
    # requested. This keeps `deployedVersions` cheap both for one service across
    # many environments (service detail) and for many services in one environment
    # (environment detail panel).
    #
    # "Deployed" here means the version_set of the most recent Cd::Deployment (by
    # started_at) for that (service, environment), regardless of deployment state --
    # matching the state-agnostic join used by .environments_for. A multi-source
    # service resolves to several versions (one per artifact source) from that
    # version_set, so the result per pair is an Array.
    #
    # `pairs` is a collection of [service_id, environment_id] tuples, or of objects
    # responding to #service_id and #environment_id (for example, Cd::ServiceEnvironmentHealth
    # rows). Returns a Hash of [service_id, environment_id] => Array of Cd::Version.
    def self.for_service_environments(pairs)
      pairs = normalize_service_environment_pairs(pairs)
      return {} if pairs.empty?

      latest = latest_deployments_by_service_environment(pairs.map(&:first).uniq, pairs.map(&:last).uniq)
      versions = versions_by_service_and_version_set(
        latest.values.map { |row| [row.service_id, row.version_set_id] }.uniq
      )

      pairs.each_with_object({}) do |(service_id, environment_id), result|
        row = latest[[service_id, environment_id]]
        result[[service_id, environment_id]] = row ? versions[[service_id, row.version_set_id]] || [] : []
      end
    end

    def self.normalize_service_environment_pairs(pairs)
      Array(pairs).map do |pair|
        if pair.respond_to?(:service_id) && pair.respond_to?(:environment_id)
          [pair.service_id, pair.environment_id]
        else
          pair.to_a.first(2)
        end
      end.uniq
    end

    # Most recent deployment (by started_at, id as tiebreaker) for each requested
    # (service, environment), keyed by [service_id, environment_id]. A single
    # DISTINCT ON query covers all services and environments, so the database
    # returns one row per pair instead of loading historical deployments into
    # Ruby, and the query count stays fixed as the number of rows grows. Selects
    # the rollout's version_set_id alongside so the caller can resolve the
    # deployed versions without another per-row query.
    def self.latest_deployments_by_service_environment(service_ids, environment_ids)
      ::Cd::Deployment
        .select(
          'DISTINCT ON (cd_deployments.service_id, cd_rollout_environments.environment_id) ' \
            'cd_deployments.service_id AS service_id',
          'cd_rollout_environments.environment_id AS environment_id',
          'cd_rollouts.version_set_id AS version_set_id'
        )
        .joins(rollout_environment: :rollout)
        .where(service_id: service_ids, cd_rollout_environments: { environment_id: environment_ids })
        .order(
          Arel.sql('cd_deployments.service_id'),
          Arel.sql('cd_rollout_environments.environment_id'),
          Arel.sql('cd_deployments.started_at DESC NULLS LAST'),
          Arel.sql('cd_deployments.id DESC')
        )
        .index_by { |row| [row.service_id, row.environment_id] }
    end

    def self.versions_by_service_and_version_set(service_version_set_pairs)
      return {} if service_version_set_pairs.empty?

      ::Cd::VersionSetEntry
        .where(
          service_id: service_version_set_pairs.map(&:first).uniq,
          version_set_id: service_version_set_pairs.map(&:last).uniq
        )
        .preload(:version)
        .group_by { |entry| [entry.service_id, entry.version_set_id] }
        .transform_values { |entries| entries.map(&:version).uniq }
    end

    # Distinct environments this version has been deployed to.
    #
    # There is no direct Version -> Environment link: `Cd::Deployment` is
    # per-service (not per-artifact-source), so a service with several
    # artifact sources can have several `VersionSetEntry` records in one
    # version_set but only ONE deployment row for that (service,
    # rollout_environment) pair. A version's own version_set_entry therefore
    # cannot be used to derive its deployment directly; instead, this matches
    # on the version's service and the version_set(s) that include it, since
    # deploying that service deploys all of its current sources' versions
    # together.
    def environments
      self.class.environments_for([self]).fetch(id, [])
    end

    private_class_method :version_set_ids_by_version_id

    private_class_method :environments_for_service_versions

    private_class_method :environments_for_service

    private_class_method :normalize_service_environment_pairs

    private_class_method :latest_deployments_by_service_environment

    private_class_method :versions_by_service_and_version_set
  end
end
