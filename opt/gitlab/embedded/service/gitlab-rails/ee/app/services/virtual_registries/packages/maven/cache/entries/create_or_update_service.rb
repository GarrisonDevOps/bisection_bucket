# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      module Cache
        module Entries
          class CreateOrUpdateService < BaseCreateOrUpdateCacheEntriesService
            extend ::Gitlab::Utils::Override

            override :entry_class
            def entry_class
              ::VirtualRegistries::Packages::Maven::Cache::Remote::Entry
            end
          end
        end
      end
    end
  end
end
