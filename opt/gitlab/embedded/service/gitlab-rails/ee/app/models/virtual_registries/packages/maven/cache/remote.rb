# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      module Cache
        module Remote
          def self.table_name_prefix
            'virtual_registries_packages_maven_cache_remote_'
          end
        end
      end
    end
  end
end
