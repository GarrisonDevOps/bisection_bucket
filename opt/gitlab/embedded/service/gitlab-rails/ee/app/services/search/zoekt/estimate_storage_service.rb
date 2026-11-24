# frozen_string_literal: true

module Search
  module Zoekt
    class EstimateStorageService
      include ActionView::Helpers::NumberHelper

      PRACTICAL_FACTOR = 0.5 # observed GitLab.com data: actual usage ~0.5x after stabilization

      def self.execute(logger:)
        new(logger: logger).execute
      end

      def initialize(logger:)
        @logger = logger
      end

      def execute
        if zoekt_configured?
          estimate_from_enabled_namespaces
        else
          estimate_from_all_namespaces
        end
      end

      private

      attr_reader :logger

      def zoekt_configured?
        Search::Zoekt::EnabledNamespace.exists?
      end

      def estimate_from_all_namespaces
        total_git_size = Namespace::RootStorageStatistics.sum(:repository_size).to_i
        num_replicas = ::Search::Zoekt::Settings.default_number_of_replicas

        log_header("Zoekt Storage Estimate (all namespaces)")
        log_note("Zoekt is not yet configured. Using system default replica count: #{num_replicas}.")
        log_note("Statistics may be stale. Run 'UpdateRootStorageStatisticsWorker' to refresh if needed.")

        log_estimate(total_git_size, num_replicas)
      end

      def estimate_from_enabled_namespaces
        provisioning_bytes = 0
        practical_bytes = 0
        replica_counts = Hash.new(0)
        # Read once outside the loop to avoid N+1 calls to ApplicationSetting.current
        # for namespaces that have no replica override.
        default_replicas = ::Search::Zoekt::Settings.default_number_of_replicas

        Search::Zoekt::EnabledNamespace.preload_storage_statistics.find_each do |en|
          git_size = en.namespace.root_storage_statistics&.repository_size.to_i
          replicas = en.number_of_replicas_override || default_replicas
          provisioning_bytes += git_size * buffer_factor * replicas
          practical_bytes += git_size * PRACTICAL_FACTOR * replicas
          replica_counts[replicas] += 1
        end

        namespace_count = replica_counts.values.sum
        reserved_bytes = Search::Zoekt::Index.sum(:reserved_storage_bytes).to_i
        used_bytes = Search::Zoekt::Node.for_search.sum(:used_bytes).to_i

        log_header("Zoekt Storage Estimate (Zoekt-enabled namespaces only)")
        log_note("Based on #{namespace_count} enabled namespace(s).")

        if replica_counts.size == 1
          num_replicas = replica_counts.each_key.first
          logger.info("Replica count:               #{num_replicas} (all namespaces)")
        else
          logger.info("Replica counts (namespaces):")
          replica_counts.sort.each do |replicas, count|
            logger.info("  #{replicas} replica(s): #{count} namespace(s)")
          end
        end

        logger.info("Estimated provisioning target (#{buffer_factor}× Git size × replicas): " \
          "#{number_to_human_size(provisioning_bytes)}")
        logger.info("Estimated practical usage (~#{PRACTICAL_FACTOR}× after stabilization): " \
          "#{number_to_human_size(practical_bytes)}")
        logger.info("Currently reserved by GitLab: #{number_to_human_size(reserved_bytes)}")
        logger.info("Currently used on nodes:      #{number_to_human_size(used_bytes)}")
      end

      def log_estimate(total_git_size, num_replicas)
        provisioning = total_git_size * buffer_factor * num_replicas
        practical = total_git_size * PRACTICAL_FACTOR * num_replicas

        logger.info("Total Git repository size:   #{number_to_human_size(total_git_size)}")
        logger.info("Default replica count:       #{num_replicas}")
        logger.info("")
        logger.info("Provisioning target (#{buffer_factor}× Git size × #{num_replicas} replica(s)): " \
          "#{number_to_human_size(provisioning)}")
        logger.info("Practical usage estimate (~#{PRACTICAL_FACTOR}× after stabilization): " \
          "#{number_to_human_size(practical)}")
        logger.info("")
        logger.info("Note: GitLab reserves #{buffer_factor}× as a buffer during indexing. " \
          "Scale Zoekt nodes to have at least #{number_to_human_size(provisioning)} available.")
      end

      def log_header(title)
        logger.info("")
        logger.info(title)
        logger.info("-" * title.length)
      end

      def log_note(msg)
        logger.info("Note: #{msg}")
      end

      def buffer_factor
        @buffer_factor ||= Search::Zoekt::Index.global_buffer_factor
      end
    end
  end
end
