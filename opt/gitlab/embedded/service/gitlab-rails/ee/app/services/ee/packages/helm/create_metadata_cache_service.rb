# frozen_string_literal: true

module EE
  module Packages
    module Helm
      module CreateMetadataCacheService
        extend ::Gitlab::Utils::Override

        private

        override :after_cache_update
        def after_cache_update(metadata_cache)
          metadata_cache.geo_handle_after_update
        end
      end
    end
  end
end
