# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      module Cache
        module Local
          def self.table_name_prefix
            'virtual_registries_packages_maven_cache_local_'
          end
        end
      end
    end
  end
end
