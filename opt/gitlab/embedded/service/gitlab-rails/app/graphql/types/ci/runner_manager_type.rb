# frozen_string_literal: true

module Types
  module Ci
    class RunnerManagerType < BaseObject
      graphql_name 'CiRunnerManager'

      connection_type_class ::Types::CountableConnectionType

      authorize :read_runner_manager

      alias_method :runner_manager, :object

      # NOTE: instance runners are exposed by default to any authenticated user,
      # remember to protect any sensitive fields
      field :architecture_name, GraphQL::Types::String, null: true,
        description: 'Architecture provided by the runner manager.'
      field :contacted_at, Types::TimeType, null: true,
        description: 'Timestamp of last contact from the runner manager.'
      field :created_at, Types::TimeType, null: true,
        description: 'Timestamp of creation of the runner manager.'
      field :executor_name, GraphQL::Types::String, null: true,
        description: 'Executor last advertised by the runner.'
      field :id, ::Types::GlobalIDType[::Ci::RunnerManager], null: false,
        description: 'ID of the runner manager.'
      field :ip_address, GraphQL::Types::String, null: true,
        description: 'IP address of the runner manager.'
      field :job_execution_status,
        Types::Ci::RunnerJobExecutionStatusEnum,
        null: true,
        description: 'Job execution status of the runner manager.'
      field :platform_name, GraphQL::Types::String, null: true,
        description: 'Platform provided by the runner manager.'
      field :revision, GraphQL::Types::String, null: true, description: 'Revision of the runner.'
      field :runner, RunnerType, null: true, description: 'Runner configuration for the runner manager.'
      field :status,
        Types::Ci::RunnerStatusEnum,
        null: false,
        description: 'Status of the runner manager.'
      field :system_id, GraphQL::Types::String,
        null: false,
        description: 'System ID associated with the runner manager.',
        method: :system_xid
      field :version, GraphQL::Types::String, null: true, description: 'Version of the runner.'

      def architecture_name
        with_cached_attributes(&:architecture)
      end

      def contacted_at
        with_cached_attributes(&:contacted_at)
      end

      def executor_name
        with_cached_attributes do |manager|
          ::Ci::RunnerManager::EXECUTOR_TYPE_TO_NAMES[manager.executor_type&.to_sym]
        end
      end

      def ip_address
        with_cached_attributes(&:ip_address)
      end

      def platform_name
        with_cached_attributes(&:platform)
      end

      def revision
        with_cached_attributes(&:revision)
      end

      def status
        with_cached_attributes(&:status)
      end

      def version
        with_cached_attributes(&:version)
      end

      def job_execution_status
        BatchLoader::GraphQL.for(runner_manager).batch(key: :running_builds_exist) do |runner_managers, loader|
          active_ids = ::Ci::RunnerManager.ids_with_running_builds_for_runner_managers(runner_managers).to_set

          runner_managers.each do |runner_manager|
            loader.call(runner_manager, active_ids.include?(runner_manager.id) ? :active : :idle)
          end
        end
      end

      private

      # Reads the cached attributes of all managers on the page together, not with one Redis GET per manager.
      # Yields the preloaded manager: it can be another instance of the same record when a query loads it twice.
      def with_cached_attributes(&block)
        unless Feature.enabled?(:ci_batch_runner_manager_cached_attributes, Feature.current_request)
          return yield(runner_manager)
        end

        Gitlab::Graphql::Lazy.with_value(runner_manager_with_cached_attributes, &block)
      end

      def runner_manager_with_cached_attributes
        BatchLoader::GraphQL.for(runner_manager).batch(key: :cached_attributes) do |runner_managers, loader|
          ::Ci::RunnerManager.preload_cached_attributes(runner_managers)

          runner_managers.each { |manager| loader.call(manager, manager) }
        end
      end
    end
  end
end

Types::Ci::RunnerManagerType.prepend_mod_with('Types::Ci::RunnerManagerType')
