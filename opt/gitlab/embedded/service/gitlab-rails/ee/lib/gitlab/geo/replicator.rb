# frozen_string_literal: true

module Gitlab
  module Geo
    # Geo Replicators are objects that know how to replicate a replicable resource
    #
    # A replicator is responsible for:
    # - firing events (producer)
    # - consuming events (consumer)
    #
    # Each replicator is tied to a specific replicable resource
    class Replicator
      include ::Gitlab::Utils::StrongMemoize
      include ::Gitlab::Geo::LogHelpers
      extend ::Gitlab::Geo::LogHelpers
      extend ::Gitlab::Geo::BatchCounter
      extend ::Gitlab::Utils::Override

      CLASS_SUFFIXES = %w[RegistryFinder RegistriesResolver].freeze

      REGISTRY_COUNT_NAMES = %i[
        registry_count synced_count failed_count verified_count verification_failed_count verification_total_count
      ].freeze

      attr_reader :model_record_id

      delegate :model, to: :class
      delegate :replication_enabled_feature_key, to: :class
      delegate :in_replicables_for_current_secondary?, to: :model_record
      delegate :replicable_title, to: :class
      delegate :replicable_title_plural, to: :class

      class << self
        delegate :find_registries_pending,
          :find_registries_needs_sync_again,
          :fail_sync_timeouts,
          to: :registry_class
      end

      # Declare supported event
      #
      # @example Declaring support for :update and :delete events
      #   class MyReplicator < Gitlab::Geo::Replicator
      #     event :updated
      #     event :deleted
      #   end
      #
      # @param [Symbol] event_name
      def self.event(event_name)
        @events ||= []
        @events << event_name.to_sym
      end
      private_class_method :event

      # List supported events
      #
      # @return [Array<Symbol>] with list of events
      def self.supported_events
        @events.dup
      end

      # Check if the replicator supports a specific event
      #
      # @param [Symbol] event_name
      # @return [Boolean] whether event support was registered in the replicator
      def self.event_supported?(event_name)
        @events.include?(event_name.to_sym)
      end

      # Return the canonical name of the replicable, e.g. "package_file".
      #
      # This can be used to retrieve the replicator class again
      # by using the `.for_replicable_name` method.
      #
      # @see .for_replicable_name
      # @return [String] slug that identifies this replicator
      def self.replicable_name
        self.name.demodulize.sub('Replicator', '').underscore
      end

      # Return the pluralized replicable name, e.g. "package_files". In general,
      # it is preferable to use the canonical replicable_name if possible.
      #
      # @return [String] slug that identifies this replicator, pluralized
      def self.replicable_name_plural
        self.replicable_name.pluralize
      end

      # Slug of the group this replicator belongs to, if replicables are grouped
      # together in the UI (e.g. the upload partitions).
      #
      # @return [String, nil] group slug, or nil when the replicator is not grouped
      def self.replicable_group = nil

      # @return [String, nil] translated group title, or nil when the replicator is not grouped
      def self.replicable_group_title = nil

      # @return [String, nil] translated group description, or nil when the replicator is not grouped
      def self.replicable_group_description = nil

      # @return [String] GraphQL registries field name. E.g. "packageFileRegistries"
      def self.graphql_field_name
        "#{self.replicable_name.camelize(:lower)}Registries"
      end

      # Return the name of the base model, formatted for API usage
      # :: and capitalisation is replaced by underscores
      # @return [String] slug that identifies the base Model name, i.e. "ci_secure_file"
      def self.model_name
        Gitlab::Geo::ModelMapper.convert_to_name(self.model)
      end

      # @return [String] slug that identifies the base Model name, pluralized, i.e. "ci_secure_files"
      def self.model_name_plural
        self.model_name.pluralize
      end

      # @return [String] GraphQL mutation registry class used by registry_class_enum.rb. E.g. "PACKAGE_FILE_REGISTRY"
      def self.graphql_mutation_registry_class
        self.registry_class.graphql_enum_key
      end

      # Return the registry related to the replicable resource
      #
      # @return [Class<Geo::BaseRegistry>] registry class
      def self.registry_class
        const_get("::Geo::#{replicable_name.camelize}Registry", false)
      end

      def self.registry_finder_class
        const_get("::Geo::#{replicable_name.camelize}RegistryFinder", false)
      end

      def self.graphql_registry_type
        const_get("::Types::Geo::#{replicable_name.camelize}RegistryType", false)
      end

      # Whether this replicator participates in the GraphQL RegistrableType union.
      # Override to false for replicators without a GraphQL registry type, e.g.
      # Geo::SupplyChainAttestationReplicator.
      # @return [Boolean]
      def self.graphql_registerable?
        true
      end

      def self.graphql_registry_id_type
        Types::GlobalIDType[registry_class]
      end

      # Given a `replicable_name`, return the corresponding replicator class
      #
      # @param [String] replicable_name the replicable slug
      # @return [Class<Geo::Replicator>] replicator implementation
      def self.for_replicable_name(replicable_name)
        replicator_class_name = "::Geo::#{replicable_name.camelize}Replicator"

        const_get(replicator_class_name, false)
      rescue NameError
        message = "Cannot find a Geo::Replicator for #{replicable_name}"
        e = NotImplementedError.new(message)

        log_error(message, e, { replicable_name: replicable_name })

        raise e
      end

      # Given the output of a replicator's `replicable_params`, reinstantiate
      # the replicator instance
      #
      # @param [String] replicable_name of a replicator instance
      # @param [Integer] replicable_id of a replicator instance
      # @return [Geo::Replicator] replicator instance
      def self.for_replicable_params(replicable_name:, replicable_id:)
        replicator_class = for_replicable_name(replicable_name)

        replicator_class.new(model_record_id: replicable_id)
      end

      def self.primary_total_count
        batch_count(model.available_replicables, model.primary_key) do
          model.available_replicables.count
        end
      end

      def self.registry_count
        batch_count(registry_class.all, registry_class.primary_key) do
          registry_class.count
        end
      end

      def self.synced_count
        batch_count(registry_class.synced, registry_class.primary_key) do
          registry_class.synced.count
        end
      end

      def self.failed_count
        batch_count(registry_class.failed, registry_class.primary_key) do
          registry_class.failed.count
        end
      end

      # Computes all secondary registry counts in one grouped pass instead of six.
      # The relation stays unfiltered so BatchCounter's end bound is a plain primary-key MAX(id).
      def self.registry_counts
        grouped = batch_count(
          registry_class.group(:state, :verification_state), # rubocop:disable CodeReuse/ActiveRecord -- unfiltered grouping for one pass
          registry_class.primary_key
        )
        fallback = grouped == ::Gitlab::Database::BatchCounter::FALLBACK

        counts = fallback ? REGISTRY_COUNT_NAMES.index_with(grouped) : sum_registry_counts(grouped)
        return counts if verification_enabled?

        counts.merge(verified_count: nil, verification_failed_count: nil, verification_total_count: nil)
      end

      def self.sum_registry_counts(grouped)
        synced = registry_class.raw_state_values(:synced)
        failed = registry_class.raw_state_values(:failed)
        verification = ::Geo::VerificationState::VERIFICATION_STATE_VALUES

        grouped.each_with_object(REGISTRY_COUNT_NAMES.index_with(0)) do |((state, verification_state), count), counts|
          counts[:registry_count] += count
          counts[:failed_count] += count if failed.include?(state)
          next unless synced.include?(state)

          counts[:synced_count] += count
          counts[:verified_count] += count if verification_state == verification[:verification_succeeded]
          counts[:verification_failed_count] += count if verification_state == verification[:verification_failed]
          counts[:verification_total_count] += count unless verification_state == verification[:verification_disabled]
        end
      end
      private_class_method :sum_registry_counts

      def self.replication_enabled?
        Feature.enabled?(replication_enabled_feature_key, type: :ops)
      end

      def self.oldest_unsynced
        oldest = registry_class.oldest_unsynced_time
        oldest.nil? ? -1 : oldest
      end

      # @example Given `Geo::PackageFileRegistryFinder`, this returns
      #   `::Geo::PackageFileReplicator`
      # @example Given `Resolver::Geo::PackageFileRegistriesResolver`, this
      #   returns `::Geo::PackageFileReplicator`
      #
      # @return [Class] a Replicator subclass
      def self.for_class_name(class_name)
        name = class_name.demodulize

        # Strip suffixes is dumb but will probably work for a while
        CLASS_SUFFIXES.each { |suffix| name.delete_suffix!(suffix) }

        const_get("::Geo::#{name}Replicator", false)
      end

      def self.replication_enabled_feature_key
        :"geo_#{replicable_name}_replication"
      end

      # Overridden by VerifiableReplicator, if it is included
      def self.verification_enabled?
        false
      end

      def self.bulk_create_delete_events_async(deleted_records)
        raise NotImplementedError
      end

      def self.bulk_create_events(events)
        ::Geo::EventLog.transaction do
          results = ::Geo::Event.insert_all!(events)

          next if results.rows.empty?

          ids = results.map { |result| { geo_event_id: result['id'], created_at: Time.current } }
          ::Geo::EventLog.insert_all!(ids)
        end

      rescue ActiveRecord::RecordInvalid, NoMethodError => e
        log_error('Geo::EventLog could not be created in bulk', e)
      end

      # Returns the appropriate SidekiqStatus expiration time for this replicator.
      # This matches the exclusive lease timeout used by the sync service to ensure
      # jobs are properly tracked even if they run for extended periods.
      #
      # @return [Integer] expiration time in seconds
      def self.status_expiration
        if respond_to?(:sync_timeout)
          int_sync_timeout = sync_timeout.to_i
          return int_sync_timeout if int_sync_timeout > 0
        end

        # Default to 8 hours for backward compatibility (repository sync uses 3 hours)
        message = "Replicator #{name} does not define sync_timeout, using default 8 hour expiration"
        Gitlab::AppLogger.warn(message)
        Gitlab::ErrorTracking.track_exception(
          StandardError.new(message),
          replicator_class: name
        )

        8.hours.to_i
      end

      # @param [ActiveRecord::Base] model_record
      # @param [Integer] model_record_id
      def initialize(model_record: nil, model_record_id: nil)
        @model_record = model_record
        @model_record_id = model_record_id || model_record&.id
      end

      # Instance of the replicable model
      #
      # @return [ActiveRecord::Base, nil]
      # @raise ActiveRecord::RecordNotFound when a model with specified model_record_id can't be found
      def model_record
        if defined?(@model_record) && @model_record
          return @model_record
        end

        if model_record_id
          @model_record = model.find(model_record_id)
        end
      end

      # Wraps an action that accesses model_record to gracefully handle
      # the case where the record has been deleted on the primary.
      # Use this in action methods (sync, consume_event_*) that trigger
      # model_record lookups.
      def with_record_not_found_handling
        yield
      rescue ActiveRecord::RecordNotFound
        fail_record_not_found!
      end

      # Marks the registry as failed when the source record has been deleted
      # on the primary but the registry still exists. This can happen when
      # the sync job runs before the delete event is processed.
      def fail_record_not_found!
        log_info("Couldn't find #{model} with 'id'=#{model_record_id}",
          replicable_name: replicable_name, model_record_id: model_record_id)

        if registry.persisted?
          registry.failed!(message: 'The source record was not found. It was likely removed from the primary site before this sync could complete.')
        end
      end

      # Publish an event with its related data
      #
      # @param [Symbol] event_name
      # @param [Hash] event_data
      def publish(event_name, **event_data)
        return unless should_publish_replication_event?
        raise ArgumentError, "Unsupported event: '#{event_name}'" unless self.class.event_supported?(event_name)

        create_event_with(
          replicable_name: self.class.replicable_name,
          event_name: event_name,
          payload: event_data
        )
      end

      # Consume an event, using the published contextual data
      #
      # This method is called by the GeoLogCursor when reading the event from the queue
      #
      # @param [Symbol] event_name
      # @param [Hash] event_data contextual data published with the event
      def consume(event_name, **event_data)
        raise ArgumentError, "Unsupported event: '#{event_name}'" unless self.class.event_supported?(event_name)

        consume_method = :"consume_event_#{event_name}"
        raise NotImplementedError, "Consume method not implemented: '#{consume_method}'" unless self.methods.include?(consume_method)

        send(consume_method, **event_data) # rubocop:disable GitlabSecurity/PublicSend
      end

      # Return the name of the replicator
      #
      # @return [String] slug that identifies this replicator
      def replicable_name
        self.class.replicable_name
      end

      # Return the registry related to the replicable resource
      #
      # @return [Class<Geo::BaseRegistry>] registry class
      def registry_class
        self.class.registry_class
      end

      # Return registry instance scoped to current model
      #
      # @return [Geo::BaseRegistry] registry instance
      def registry
        registry_class.for_model_record_id(model_record_id)
      end

      # Return exactly the data needed by `for_replicable_params` to
      # reinstantiate this Replicator elsewhere.
      #
      # @return [Hash] the replicable name and ID
      def replicable_params
        { replicable_name: replicable_name, replicable_id: model_record_id }
      end

      def geo_handle_after_create
        return unless Gitlab::Geo.primary?

        publish(:created, **created_params)
        after_verifiable_update if respond_to?(:after_verifiable_update)
      end

      # @param params [Hash, nil] deleted_params read before the destroy committed, for a caller
      #        that publishes after the commit, when the record may no longer provide them
      def geo_handle_after_destroy(params = nil)
        return unless Gitlab::Geo.primary?

        publish(:deleted, **(params || deleted_params))
      end

      def geo_handle_after_update
        return unless Gitlab::Geo.primary?

        publish(:updated, **updated_params)
        after_verifiable_update if respond_to?(:after_verifiable_update)
      end

      def created_params
        event_params
      end

      def deleted_params
        event_params
      end

      def updated_params
        event_params
      end

      def event_params
        {
          "model_record_id" => model_record.id,
          "correlation_id" => Labkit::Correlation::CorrelationId.current_id
        }
      end

      # Returns whether the actual data exists
      #
      # The implementation must do a hard check because we are doing these
      # checks for replication or verification purposes, so we should not just
      # trust the data in the DB if we don't absolutely have to.
      #
      # @abstract
      # @return [Boolean] whether the actual data exists
      def resource_exists?
        raise NotImplementedError, "#{self.class} does not implement #{__method__}"
      end
      strong_memoize_attr :resource_exists?

      protected

      # This method can be overridden in a replicator class to add other
      # conditionals for accepting events
      def should_publish_replication_event?
        self.class.replication_enabled?
      end

      # Store an event on the database
      #
      # @example Create an event
      #   create_event_with(key: key)
      #
      # @param [Hash] **params context information that will be stored in the event table
      # @return [ApplicationRecord, nil] event instance that was just persisted, otherwise nil
      def create_event_with(**params)
        return unless Gitlab::Geo.primary?
        return unless Gitlab::Geo.secondary_nodes.any?

        event = nil
        ::Geo::Event.transaction do
          event = ::Geo::Event.create!(**params)

          # Only works with the new geo_events at the moment because we need to know which foreign key to use
          ::Geo::EventLog.create!(geo_event: event)
        end

        event if event&.persisted?
      rescue ActiveRecord::RecordInvalid, NoMethodError => e
        log_error("::Geo::Event could not be created", e, params)

        nil
      end

      def current_node
        Gitlab::Geo.current_node
      end
    end
  end
end
