# frozen_string_literal: true

module Gitlab
  module Geo
    extend ::Gitlab::Utils::StrongMemoize

    OauthApplicationUndefinedError = Class.new(StandardError)
    GeoNodeNotFoundError = Class.new(StandardError)
    InvalidDecryptionKeyError = Class.new(StandardError)
    InvalidSignatureTimeError = Class.new(StandardError)

    CACHE_KEYS = %i[
      primary_node_url
      primary_internal_url
      node_enabled
      proxy_extra_data
    ].freeze

    API_SCOPE = 'geo_api'
    GEO_PROXIED_HEADER = 'HTTP_GITLAB_WORKHORSE_GEO_PROXY'
    GEO_PROXIED_EXTRA_DATA_HEADER = 'HTTP_GITLAB_WORKHORSE_GEO_PROXY_EXTRA_DATA'

    # TODO: Avoid having to maintain a list. Discussions related to possible
    # solutions can be found at
    # https://gitlab.com/gitlab-org/gitlab/-/issues/227693
    REPLICATOR_CLASSES = [
      ::Geo::AbuseReportUploadReplicator,
      ::Geo::AchievementUploadReplicator,
      ::Geo::AlertManagementMetricImageUploadReplicator,
      ::Geo::AppearanceUploadReplicator,
      ::Geo::BulkImportExportUploadUploadReplicator,
      ::Geo::CiSecureFileReplicator,
      ::Geo::ContainerRepositoryReplicator,
      ::Geo::DependencyListExportPartUploadReplicator,
      ::Geo::DependencyListExportUploadReplicator,
      ::Geo::DependencyProxyBlobReplicator,
      ::Geo::DependencyProxyManifestReplicator,
      ::Geo::DesignManagementActionUploadReplicator,
      ::Geo::DesignManagementRepositoryReplicator,
      ::Geo::GroupUploadReplicator,
      ::Geo::GroupWikiRepositoryReplicator,
      ::Geo::ImportExportUploadUploadReplicator,
      ::Geo::IssuableMetricImageUploadReplicator,
      ::Geo::JobArtifactReplicator,
      ::Geo::LfsObjectReplicator,
      ::Geo::MergeRequestDiffReplicator,
      ::Geo::OrganizationDetailUploadReplicator,
      ::Geo::PackageFileReplicator,
      ::Geo::PackagesDebianProjectComponentFileReplicator,
      ::Geo::PackagesHelmMetadataCacheReplicator,
      ::Geo::PackagesNugetSymbolReplicator,
      ::Geo::PagesDeploymentReplicator,
      ::Geo::PersonalSnippetUploadReplicator,
      ::Geo::PipelineArtifactReplicator,
      ::Geo::ProjectImportExportRelationExportUploadUploadReplicator,
      ::Geo::ProjectRepositoryReplicator,
      ::Geo::ProjectTopicUploadReplicator,
      ::Geo::ProjectUploadReplicator,
      ::Geo::ProjectWikiRepositoryReplicator,
      ::Geo::SnippetRepositoryReplicator,
      ::Geo::SupplyChainAttestationReplicator,
      ::Geo::TerraformStateVersionReplicator,
      ::Geo::UploadReplicator,
      ::Geo::UserPermissionExportUploadUploadReplicator,
      ::Geo::UserUploadReplicator,
      ::Geo::VulnerabilityArchiveExportUploadReplicator,
      ::Geo::VulnerabilityExportPartUploadReplicator,
      ::Geo::VulnerabilityExportUploadReplicator,
      ::Geo::VulnerabilityRemediationUploadReplicator
    ].freeze

    # We "regenerate" an 1hour valid JWT every 30 minutes, resulting in
    # a token valid for at least 30 minutes at every given time, even if
    # the internal API is not available to serve a new one for up to 30m.
    # The primary shouldn't hard fail if this isn't valid, it just doesn't
    # know the proxying node.
    PROXY_JWT_VALIDITY_PERIOD = 1.hour
    PROXY_JWT_CACHE_EXPIRY = 30.minutes

    NODE_MEMOIZATION_EXPIRY = 2.minutes

    def self.primary_node
      GeoNode.primary_node
    end

    def self.primary_node_url
      cache_value(:primary_node_url) { primary_node&.url }
    end

    def self.primary_node_internal_url
      cache_value(:primary_internal_url) { primary_node&.internal_url }
    end

    def self.secondary_nodes
      strong_memoize_with_expiration(:secondary_nodes, NODE_MEMOIZATION_EXPIRY) { GeoNode.secondary_nodes }
    end

    def self.secondary_node?(node_id)
      secondary_nodes.any? { |node| node.id.to_s == node_id.to_s }
    end

    def self.current_node
      strong_memoize_with_expiration(:current_node, NODE_MEMOIZATION_EXPIRY) { GeoNode.current_node }
    end

    def self.oauth_authentication
      return unless Gitlab::Geo.secondary?

      Gitlab::Geo.current_node.oauth_application || raise(OauthApplicationUndefinedError)
    end

    def self.oauth_authentication_uid
      oauth_authentication&.uid
    end

    def self.oauth_authentication_secret
      oauth_authentication&.secret
    end

    def self.proxy_extra_data
      cache_value(:proxy_extra_data, l2_cache_expires_in: PROXY_JWT_CACHE_EXPIRY) { uncached_proxy_extra_data }
    end

    def self.enabled?
      cache_value(:node_enabled) { GeoNode.exists? }
    end

    def self.uncached_proxy_extra_data
      # Extra data that can be computed/sent for all proxied requests.
      #
      # We're currently only interested in the signing node which can
      # be figured out from the signing key, so not sending any actual
      # extra data.
      data = {}

      Gitlab::Geo::SignedData.new(geo_node: current_node, validity_period: PROXY_JWT_VALIDITY_PERIOD)
        .sign_and_encode_data(data)
    rescue GeoNodeNotFoundError, OpenSSL::Cipher::CipherError
      nil
    end

    def self.connected?
      # GeoNode#connected? only attempts to use existing DB connections so it can't
      # be relied upon in initializers, without this active DB connectivity check.
      active_db_connection = begin
        GeoNode.connection_pool.with_connection(&:active?)
      rescue StandardError
        false
      end

      active_db_connection && GeoNode.table_exists?
    end

    def self.primary?
      enabled? && current_node&.primary?
    end

    def self.secondary?(infer_without_database: false)
      return secondary_check_without_db_connection if infer_without_database

      enabled? && current_node&.secondary?
    end

    def self.org_migration_target?
      enabled? && current_node&.org_migration_target?
    end

    def self.secondary_or_org_migration_target?
      enabled? && current_node&.secondary_or_org_migration_target?
    end

    # - All data in a secondary Geo site was replicated there => return true
    # - All data in a primary Geo site is the source data => return false
    # - All data in a non-Geo site is the source data => return false
    # - Only selected orgs in an org migration target cell were replicated there
    def self.replica_org?(organization)
      # A secondary replicates everything
      return true if secondary?

      # A primary never has replica data
      return false if primary?

      # A non-Geo site never has replica data
      return false unless org_migration_target?

      # An org migration target only has replica data for its selected orgs
      raise ArgumentError, "Organization cannot be nil" if organization.nil?

      current_node.selective_sync_by_organizations? &&
        current_node.organizations.include?(organization)
    end

    def self.replica_namespace?(namespace)
      raise ArgumentError, "Namespace cannot be nil" if namespace.nil?

      replica_org?(namespace.organization)
    end

    def self.replica_project?(project)
      raise ArgumentError, "Project cannot be nil" if project.nil?

      replica_org?(project.organization)
    end

    def self.replica_organization_id?(organization_id)
      raise ArgumentError, "Organization ID cannot be nil" if organization_id.nil?

      organization = ::Organizations::Organization.find(organization_id)

      replica_org?(organization)
    end

    def self.replica_namespace_id?(namespace_id)
      raise ArgumentError, "Namespace ID cannot be nil" if namespace_id.nil?

      namespace = ::Namespace.find(namespace_id)

      replica_namespace?(namespace)
    end

    def self.replica_project_id?(project_id)
      raise ArgumentError, "Project ID cannot be nil" if project_id.nil?

      project = ::Project.find(project_id)

      replica_project?(project)
    end

    # Polymorphic dispatcher for checking if a sharding object is a replica
    #
    # @param sharding_object [Project, Namespace, Organizations::Organization]
    #   the sharding object to check
    # @return [Boolean] true if the sharding object is a replica
    # @raise [ArgumentError] if the sharding object type is unsupported
    def self.replica_sharding_object?(sharding_object)
      case sharding_object
      when ::Project
        replica_project?(sharding_object)
      when ::Namespace # Also matches Group, ProjectNamespace, and other Namespace subclasses
        replica_namespace?(sharding_object)
      when ::Organizations::Organization
        replica_org?(sharding_object)
      else
        raise ArgumentError,
          "Unsupported sharding object type: #{sharding_object.class}"
      end
    end

    # Skips the given block if the sharding object is a replica.
    #
    # Use this to guard write operations that should not run for data
    # managed by another site or cell. Readable by non-Geo engineers:
    #
    #   Gitlab::Geo.skip_writes_if_replica(project) do
    #     SomeWorker.perform_async(project.id)
    #   end
    #
    # For workers that need per-instance logging and memoization, use
    # the Geo::SkipReplica concern instead.
    #
    # @param sharding_object [Project, Namespace, Organizations::Organization]
    # @yield Executed only when the sharding object is NOT a replica
    # @return [nil] when skipped, or the block's return value
    def self.skip_writes_if_replica(sharding_object)
      return if replica_sharding_object?(sharding_object)

      yield
    end

    def self.secondary_check_without_db_connection
      # In tests, we almost always have a tracking DB configured to make running tests easier,
      # and in CI we can't rely on the node name, so this is disabled (but tested as well)
      return false if Rails.env.test?

      # In the GDK, the tracking database is usually configured for the primary node as well to
      # make running tests easier.
      #
      # GDK sets `GDK_GEO_SECONDARY=1` when `geo.secondary` => `true` in
      # `gdk.yml` for Rails processes in `Procfile`. Note that here we are
      # preferring to let Geo secondary sites in development execute and depend
      # on `geo_database_configured?` (more like production).
      return false if Rails.env.development? && !gdk_geo_secondary?

      ::Gitlab::Geo.geo_database_configured?
    end

    def self.gdk_geo_secondary?
      Gitlab::Utils.to_boolean(ENV['GDK_GEO_SECONDARY'])
    end

    def self.current_node_misconfigured?
      enabled? && current_node.nil?
    end

    def self.current_node_enabled?
      # No caching of the enabled! If we cache it and an admin
      # disables this node, an active Geo::RepositoryRegistrySyncWorker
      # and Geo::RegistrySyncWorker would keep going for up to
      # max run time after the node was disabled.
      Gitlab::Geo.current_node.reset.enabled?
    end

    def self.geo_database_configured?
      ::Gitlab::Database.has_config?(:geo)
    end

    def self.primary_node_configured?
      Gitlab::Geo.primary_node.present?
    end

    def self.secondary_with_primary?
      secondary? && primary_node_configured?
    end

    def self.secondary_with_unified_url?
      secondary_with_primary? && primary_node_url == current_node.url
    end

    def self.proxied_request?(env)
      env[GEO_PROXIED_HEADER] == '1'
    end

    def self.proxied_site(env)
      return unless ::Gitlab::Geo.primary?
      return unless proxied_request?(env) && env[GEO_PROXIED_EXTRA_DATA_HEADER].present?

      # Note: The env argument is not needed after the first call within a request context.
      #       All subsequent calls within a request should return the same GeoNode record.
      SafeRequestStore.fetch(:proxied_site) do
        signed_data = Gitlab::Geo::SignedData.new
        signed_data.decode_data(env[GEO_PROXIED_EXTRA_DATA_HEADER])

        signed_data.geo_node
      end
    end

    # JWT scope for a repository path, as used by GitSSHProxy (producer) and
    # GitHttpController (consumer). Accepts "/group/repo.git" or "group/repo.git".
    def self.repository_scope(repository_path)
      repository_path.delete_prefix('/').delete_suffix('.git')
    end

    def self.license_allows?
      ::License.feature_available?(:geo)
    end

    def self.configure_cron_jobs!
      manager = CronManager.new
      manager.create_watcher!
      manager.execute
    end

    def self.l1_cache
      SafeRequestStore[:geo_l1_cache] ||=
        Gitlab::Cache::JsonCaches::RedisKeyed.new(namespace: :geo, backend: ::Gitlab::ProcessMemoryCache.cache_backend,
          cache_key_strategy: :version)
    end

    def self.l2_cache
      SafeRequestStore[:geo_l2_cache] ||= Gitlab::Cache::JsonCaches::RedisKeyed.new(namespace: :geo,
        cache_key_strategy: :version)
    end

    # Default to a short expire time as we can't manually expire on a secondary node
    # so short-lived or data that can get frequently updated doesn't persist too much
    def self.cache_value(raw_key, as: nil, l1_cache_expires_in: 1.minute, l2_cache_expires_in: 2.minutes, &block)
      l1_cache.fetch(raw_key, as: as, expires_in: l1_cache_expires_in) do
        l2_cache.fetch(raw_key, as: as, expires_in: l2_cache_expires_in) { yield }
      end
    end

    def self.expire_cache!
      clear_memoization(:current_node)
      clear_memoization(:secondary_nodes)

      expire_cache_keys!(CACHE_KEYS)
    end

    def self.expire_cache_keys!(keys)
      keys.each do |key|
        l1_cache.expire(key)
        l2_cache.expire(key)
      end

      true
    end

    def self.generate_access_keys
      # Inspired by S3
      {
        access_key: generate_random_string(20),
        secret_access_key: generate_random_string(40)
      }
    end

    def self.generate_random_string(size)
      # urlsafe_base64 may return a string of size * 4/3
      SecureRandom.urlsafe_base64(size)[0, size]
    end

    def self.allowed_ip?(ip)
      allowed_ips = ::Gitlab::CurrentSettings.current_application_settings.geo_node_allowed_ips

      Gitlab::CIDR.new(allowed_ips).match?(ip)
    end

    def self.interacting_with_primary_message(url)
      return unless url

      # This is formatted like this to fit into the console 'box', e.g.
      #
      # remote:
      # remote: This request to a Geo secondary node will be forwarded to the
      # remote: Geo primary node:
      # remote:
      # remote:   <url>
      # remote:
      template = <<~STR
        This request to a Geo secondary node will be forwarded to the
        Geo primary node:

          %{url}
      STR

      format(_(template), url: url)
    end

    # Registry classes for every replicator, derived from REPLICATOR_CLASSES so the
    # replicator list stays the single source of truth. Each replicator resolves its own
    # registry via `.registry_class`. Consumed by RegistryConsistencyWorker::REGISTRY_CLASSES.
    def self.registry_classes
      REPLICATOR_CLASSES.map(&:registry_class)
    end

    def self.replication_enabled_replicator_classes
      REPLICATOR_CLASSES.select(&:replication_enabled?)
    end

    def self.blob_replicator_classes
      replication_enabled_replicator_classes.select do |replicator|
        replicator.ancestors.include?(::Geo::BlobReplicatorStrategy)
      end
    end

    def self.repository_replicator_classes
      replication_enabled_replicator_classes.select do |replicator|
        replicator.ancestors.include?(::Geo::RepositoryReplicatorStrategy) ||
          replicator == ::Geo::ContainerRepositoryReplicator
      end
    end

    # Unlike its siblings, this includes classes whose replication is disabled.
    def self.upload_partition_replicator_classes
      REPLICATOR_CLASSES.select { |replicator| replicator.replicable_group == 'uploads' }
    end

    def self.verification_enabled_replicator_classes
      REPLICATOR_CLASSES.select(&:verification_enabled?)
    end

    # The maximum number of verification jobs to run concurrently on the current
    # node, across all Replicator classes combined.
    #
    # Geo::VerificationBatchWorker handles every Replicator class through a single
    # worker class, and LimitedCapacity keys its concurrency pool on the worker
    # class name. So all Replicator classes share one pool: this is a global limit
    # on concurrent verification jobs, not a per-class limit.
    #
    # @return [Integer] the maximum number of concurrent verification jobs (at least 1)
    def self.verification_concurrency_limit
      [1, current_node.verification_max_capacity].max # at least 1
    end

    def self.uncached_queries(&block)
      raise 'No block given' unless block

      ApplicationRecord.uncached do
        if ::Gitlab::Geo.secondary_or_org_migration_target?
          ::Geo::TrackingBase.uncached(&block)
        else
          yield
        end
      end
    end

    def self.primary_pipeline_refs(project_id)
      api_url = "/geo/repositories/project-#{project_id}/pipeline_refs"
      results = ::Geo::PrimaryApiRequestService.new(api_url, Net::HTTP::Get).execute

      return [] unless results

      results['pipeline_refs']
    end

    # Checks if the Feature flag `geo_postgresql_replication_agnostic` is enabled.
    # @return [Boolean] whether the feature flag is enabled or not.
    def self.postgresql_replication_agnostic_enabled?
      Feature.enabled?(:geo_postgresql_replication_agnostic, :instance, type: :wip)
    end

    def self.org_mover_extend_selective_sync_to_primary_checksumming?
      Feature.enabled?(:org_mover_extend_selective_sync_to_primary_checksumming, type: :ops) # rubocop:disable Gitlab/FeatureFlagWithoutActor -- Checksumming is instance wide
    end

    def self.geo_selective_sync_by_organizations_enabled?
      ::Feature.enabled?(:geo_selective_sync_by_organizations, :instance)
    end
  end
end
