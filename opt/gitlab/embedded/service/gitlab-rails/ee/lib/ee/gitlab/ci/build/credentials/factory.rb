# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Build
        module Credentials
          module Factory
            extend ::Gitlab::Utils::Override

            private

            override :providers
            def providers
              super + [::Gitlab::Ci::Build::Credentials::Registry::ArtifactRegistry]
            end
          end
        end
      end
    end
  end
end
