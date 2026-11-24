# frozen_string_literal: true

module Mutations
  module Analytics
    module Orbit
      class InstanceStartTrial < BaseMutation
        graphql_name 'OrbitInstanceStartTrial'

        authorize :start_orbit_trial

        authorize_granular_token permissions: :start_orbit_trial,
          boundary: :instance,
          boundary_type: :instance,
          assignable_when: [:admin, :self_managed]

        field :access, ::Types::Analytics::Orbit::AccessType,
          null: true,
          description: 'Instance Orbit access state after starting the trial.'

        def resolve
          authorize!(:global)

          result = ::Analytics::Orbit::Billing.instance_account.start_trial(by: current_user)

          { access: :instance, errors: result.success? ? [] : [result.message] }
        end
      end
    end
  end
end
