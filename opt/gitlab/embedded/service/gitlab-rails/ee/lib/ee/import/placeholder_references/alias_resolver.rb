# frozen_string_literal: true

module EE
  module Import
    module PlaceholderReferences
      module AliasResolver
        EE_ALIASES = {
          "ApprovalProjectRulesUser" => {
            1 => {
              model: ::ApprovalProjectRulesUser,
              columns: { "user_id" => "user_id" }
            }
          },
          "BoardAssignee" => {
            1 => {
              model: ::BoardAssignee,
              columns: { "assignee_id" => "assignee_id" }
            }
          },
          "ProtectedBranch::UnprotectAccessLevel" => {
            1 => {
              model: ::ProtectedBranch::UnprotectAccessLevel,
              columns: { "user_id" => "user_id" }
            }
          },
          "ProtectedEnvironments::DeployAccessLevel" => {
            1 => {
              model: ::ProtectedEnvironments::DeployAccessLevel,
              columns: { "user_id" => "user_id" }
            }
          },
          "ResourceIterationEvent" => {
            1 => {
              model: ::ResourceIterationEvent,
              columns: { "user_id" => "user_id" }
            }
          }
        }.freeze

        private_constant :EE_ALIASES

        def aliases
          @aliases ||= super.merge(EE_ALIASES)
        end
      end
    end
  end
end
