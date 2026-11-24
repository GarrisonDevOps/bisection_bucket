# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module ProjectConfig
        module Source
          extend ::Gitlab::Utils::Override

          override :initialize
          def initialize(scan_profile_context: nil, **args)
            super(**args)
            @scan_profile_context = scan_profile_context
          end

          attr_reader :scan_profile_context
        end
      end
    end
  end
end
