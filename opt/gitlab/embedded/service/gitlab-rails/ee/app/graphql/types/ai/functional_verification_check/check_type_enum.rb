# frozen_string_literal: true

module Types
  module Ai
    module FunctionalVerificationCheck
      class CheckTypeEnum < BaseEnum
        graphql_name 'FunctionalVerificationCheckType'
        description 'Type of functional verification check.'

        ::Ai::DuoAgentPlatform::FunctionalVerificationRun::CHECK_TYPES.each_key do |check_type|
          value check_type.upcase, value: check_type, description: "#{check_type.to_s.titleize} check."
        end
      end
    end
  end
end
