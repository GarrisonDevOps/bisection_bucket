# frozen_string_literal: true

module VirtualRegistries
  module Container
    module Cache
      def self.table_name_prefix
        'virtual_registries_container_cache_'
      end
    end
  end
end
