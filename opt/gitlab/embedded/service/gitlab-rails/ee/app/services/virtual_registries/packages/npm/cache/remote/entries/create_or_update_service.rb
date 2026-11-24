# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Npm
      module Cache
        module Remote
          module Entries
            class CreateOrUpdateService < BaseCreateOrUpdateCacheEntriesService
              extend ::Gitlab::Utils::Override

              override :entry_class
              def entry_class
                ::VirtualRegistries::Packages::Npm::Cache::Remote::Entry
              end
            end
          end
        end
      end
    end
  end
end
