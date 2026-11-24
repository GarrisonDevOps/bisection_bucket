# frozen_string_literal: true

module EE
  module Mutations
    module Ci
      module Runner
        module Create
          extend ActiveSupport::Concern

          prepended do
            # rubocop:disable Cop/InjectEnterpriseEditionModule -- This is not a typical EE module include
            # that happens from the non-EE code part. It's a "standard" include of an EE module inside
            # other EE module
            include EE::Mutations::Ci::Runner::CommonMutationArguments
            # rubocop:enable Cop/InjectEnterpriseEditionModule

            argument :token_expires_at, ::Types::TimeType,
              required: false,
              description: 'Token expiration time (ISO 8601 format). ' \
                'Must be between 5 minutes and 21 days in the future, ' \
                'and cannot exceed instance/group/project limits.'
            argument :token_rotation_deadline, ::Types::TimeType,
              required: false,
              description: 'Deadline for token rotation (ISO 8601 format). ' \
                'Requires tokenExpiresAt. Must be <= tokenExpiresAt. ' \
                'Setting both to the same value disables token rotation.',
              experiment: { milestone: '18.10' }
          end
        end
      end
    end
  end
end
