# frozen_string_literal: true

module EE
  module DependencyProxy
    module CleanupDependencyProxyWorker
      extend ::Gitlab::Utils::Override

      VREG_CACHE_ENTRY_CLASSES = [
        ::VirtualRegistries::Packages::Maven::Cache::Remote::Entry,
        ::VirtualRegistries::Container::Cache::Entry,
        ::VirtualRegistries::Container::Cache::Remote::Entry
      ].freeze

      override :perform
      def perform
        super
        enqueue_vreg_packages_cache_entry_cleanup_job
      end

      private

      def enqueue_vreg_packages_cache_entry_cleanup_job
        VREG_CACHE_ENTRY_CLASSES.each do |klass|
          if klass.pending_destruction.any?
            ::VirtualRegistries::Cache::DestroyOrphanEntriesWorker.perform_with_capacity(klass.name)
          end
        end
      end
    end
  end
end
