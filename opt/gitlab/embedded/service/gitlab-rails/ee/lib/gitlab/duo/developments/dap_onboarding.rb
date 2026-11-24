# frozen_string_literal: true

module Gitlab
  module Duo
    module Developments
      class DapOnboarding
        def self.execute
          puts "Onboarding Duo Agent Platform..."

          admin_user = User.find_by_username('root')
          raise "Please ensure an admin user exists." unless admin_user&.can_admin_all_resources?

          organization = ::Organizations::Organization.find_by_id(1)

          onboarding_service = ::Ai::DuoWorkflows::OnboardingService.new(
            current_user: admin_user,
            organization: organization
          )

          result = onboarding_service.execute

          if result.success?
            puts "Duo Agent Platform onboarded successfully"
          else
            puts "Onboarding failed: #{result.message}"
          end
        end
      end
    end
  end
end
