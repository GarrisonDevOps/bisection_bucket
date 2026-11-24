# frozen_string_literal: true

module Resolvers
  module Ai
    module FunctionalVerificationCheck
      class StatusResolver < BaseResolver
        type ::Types::Ai::FunctionalVerificationCheck::StatusType, null: true

        argument :check_type, ::Types::Ai::FunctionalVerificationCheck::CheckTypeEnum,
          required: true,
          description: 'Type of functional verification check to read the status of.'

        def resolve(check_type:)
          case check_type
          when :agentic_chat
            resolve_agentic_chat
          else
            raise_resource_not_available_error!("#{check_type} is not a supported check type")
          end
        end

        private

        def resolve_agentic_chat
          return unless ::Ai::DuoAgentPlatformVerificationCheck.agentic_chat_verification_check_enabled?(current_user)

          ::Ai::DuoAgentPlatform::FunctionalVerificationRunService.new(check_type: :agentic_chat).read
        end
      end
    end
  end
end
