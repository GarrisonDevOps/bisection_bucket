# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Pipeline
        module Chain
          module Validate
            module AfterConfig
              extend ::Gitlab::Utils::Override

              override :perform!
              def perform!
                begin
                  ::Users::IdentityVerification::AuthorizeCi.new(user: current_user, project: project)
                    .authorize_run_jobs!
                rescue ::Users::IdentityVerification::Error => e
                  return error(e.message, failure_reason: :user_not_verified)
                end

                super
              end
            end
          end
        end
      end
    end
  end
end
