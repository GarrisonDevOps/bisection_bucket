# frozen_string_literal: true

module Mutations
  module ComplianceManagement
    module Standards
      class RefreshAdherenceChecks < BaseMutation
        graphql_name 'RefreshStandardsAdherenceChecks'

        include Mutations::ResolvesGroup

        authorize :read_compliance_dashboard
        authorize_granular_token permissions: :read_compliance_dashboard,
          boundary_argument: :group_path, boundary_type: :group

        argument :group_path, GraphQL::Types::ID,
          required: true,
          description: 'Group path.'

        field :adherence_checks_status, ::Types::ComplianceManagement::StandardsAdherenceChecksStatusType,
          null: true,
          description: 'Progress of standards adherence checks.'

        def resolve(group_path:)
          group = authorized_find!(group_path)

          response = ::ComplianceManagement::Standards::RefreshService
                       .new(group: group, current_user: current_user).execute

          if response.success?
            payload = response.payload.transform_keys(&:to_sym)

            adherence_checks_status = { started_at: Time.parse(payload[:started_at]),
                                        total_checks: payload[:total_checks],
                                        checks_completed: payload[:checks_completed] }

            { adherence_checks_status: adherence_checks_status, errors: [] }
          else
            { errors: response.errors }
          end
        end

        private

        def find_object(group_path)
          resolve_group(full_path: group_path)
        end
      end
    end
  end
end
