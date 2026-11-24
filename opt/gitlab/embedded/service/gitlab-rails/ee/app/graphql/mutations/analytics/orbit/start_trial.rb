# frozen_string_literal: true

module Mutations
  module Analytics
    module Orbit
      class StartTrial < BaseMutation
        graphql_name 'OrbitStartTrial'

        include Mutations::ResolvesGroup

        authorize :start_orbit_trial

        authorize_granular_token permissions: :start_orbit_trial,
          boundary_argument: :group_path,
          boundary_type: :group,
          assignable_when: [:saas]

        argument :group_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the top-level group.'

        field :group, ::Types::GroupType,
          null: true,
          description: 'Group the trial was requested for, also returned on error. ' \
            'Read `orbit { enabled access { trial } }` from it.'

        def resolve(group_path:)
          group = authorized_find!(group_path: group_path)

          result = ::Analytics::Orbit::Billing.account_for(group).start_trial(by: current_user)

          { group: group, errors: result.success? ? [] : [result.message] }
        end

        private

        def find_object(group_path:)
          resolve_group(full_path: group_path)
        end
      end
    end
  end
end
