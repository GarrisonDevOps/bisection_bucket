# frozen_string_literal: true

module VirtualRegistries
  module Container
    module Cache
      module Remote
        def self.table_name_prefix
          'virtual_registries_container_cache_remote_'
        end
      end
    end
  end
end
