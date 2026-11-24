# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module ProjectConfig
        extend ::Gitlab::Utils::Override

        EE_SOURCES = [
          ::Gitlab::Ci::ProjectConfig::SecurityScanProfile
        ].freeze

        override :initialize
        def initialize(scan_profile_context: nil, **args)
          @scan_profile_context = scan_profile_context # before super calls find_source
          super(**args)
        end

        override :find_source
        def find_source(**args)
          super(**args, scan_profile_context: scan_profile_context)
        end

        private

        attr_reader :scan_profile_context

        def standard_sources
          super + EE_SOURCES
        end
      end
    end
  end
end
