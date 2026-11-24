# frozen_string_literal: true

module Geo
  # Worker concern that adds per-instance logging to
  # Gitlab::Geo.skip_writes_if_replica. Logs once per sharding object
  # per worker instance to avoid spamming.
  #
  # For non-worker code, call Gitlab::Geo.skip_writes_if_replica directly.
  module SkipReplica
    include ::Gitlab::Utils::StrongMemoize
    extend ::Gitlab::Utils::Override

    override :skip_writes_if_replica
    def skip_writes_if_replica(sharding_object)
      if skip_writes_if_replica?(sharding_object)
        log_skip(sharding_object)

        return
      end

      yield
    end

    override :skip_writes_if_replica?
    def skip_writes_if_replica?(sharding_object)
      ::Gitlab::Geo.replica_sharding_object?(sharding_object)
    end

    private

    def log_skip(sharding_object)
      strong_memoize_with(:log_skip, sharding_object) do
        ::Gitlab::Geo::Logger.info(
          message: 'skip_writes_if_replica skipped a block because the sharding object is a replica',
          sharding_object_class: sharding_object.class.name,
          sharding_object_id: sharding_object.id
        )
      end
    end
  end
end
