# frozen_string_literal: true

module Geo
  # Backs the `uploadRegistries` GraphQL field with a UNION ALL of the upload partition registries.
  # The upload ID is the union key: unique across partitions (shared `uploads_id_seq`), unlike registry IDs.
  class UploadPartitionRegistriesFinder
    include Gitlab::Allowable

    def initialize(current_user, params = {})
      @current_user = current_user
      @params = params
    end

    def execute
      return ::Geo::UploadRegistry.none unless can?(current_user, :read_all_geo)
      return ::Geo::UploadRegistry.none if replicators.empty?

      branches = replicators.map { |r| branch(r) }
      # Rows carry upload IDs as `id`; saving one would write an unrelated file_registry row.
      registry_entries = ::Geo::UploadRegistry.from_union(branches, remove_duplicates: false)
        .readonly # rubocop:disable CodeReuse/ActiveRecord -- guards the union rows against writes
      registry_entries = by_id(registry_entries)
      registry_entries = by_replication_state(registry_entries)
      registry_entries = by_verification_state(registry_entries)
      registry_entries = by_keyword(registry_entries)
      ordered(registry_entries)
    end

    private

    attr_reader :current_user, :params

    def replicators
      @replicators ||= ::Gitlab::Geo.upload_partition_replicator_classes.select(&:replication_enabled?)
    end

    def verification_disabled?
      replicators.any? { |replicator| !replicator.verification_enabled? }
    end

    def branch(replicator)
      registry_class = replicator.registry_class
      table = registry_class.arel_table
      foreign_key = table[registry_class.model_foreign_key]

      overrides = {
        'id' => foreign_key,
        'file_id' => foreign_key,
        'missing_on_primary' => Arel.sql('false')
      }

      projections = ::Geo::UploadRegistry.column_names.map do |name|
        (overrides[name] || table[name]).as(::Geo::UploadRegistry.connection.quote_column_name(name))
      end
      projections << Arel::Nodes.build_quoted(replicator.replicable_name).as('replicable_name')

      registry_class.select(projections)
    end

    def by_id(registry_entries)
      return registry_entries if params[:ids].blank?

      registry_entries.id_in(params[:ids])
    end

    def by_replication_state(registry_entries)
      return registry_entries if params[:replication_state].blank?

      registry_entries.with_state(params[:replication_state])
    end

    def by_verification_state(registry_entries)
      if verification_disabled? && params.key?(:verification_state)
        raise ArgumentError, "Filtering by verification_state is not supported " \
          "because verification is not enabled for #{::Upload}"
      end

      return registry_entries if params[:verification_state].blank?

      registry_entries.available_verifiables.with_verification_state(:"verification_#{params[:verification_state]}")
    end

    def by_keyword(registry_entries)
      return registry_entries if params[:keyword].blank?

      registry_entries.with_search(params[:keyword])
    end

    def ordered(registry_entries)
      if params[:sort].to_s.include?('verified_at') && verification_disabled?
        raise ArgumentError, "Sorting by verified_at is not supported " \
          "because verification is not enabled for #{::Upload}"
      end

      registry_entries.ordered_by(params[:sort])
    end
  end
end
