# frozen_string_literal: true

module EE
  module Gitlab
    module Encryption
      module DbKeyBaseRotation
        module TokenDigestsStatus
          extend ::Gitlab::Utils::Override

          private

          override :token_relations
          def token_relations
            super + [::Ci::RunnerControllerToken.active]
          end
        end
      end
    end
  end
end
