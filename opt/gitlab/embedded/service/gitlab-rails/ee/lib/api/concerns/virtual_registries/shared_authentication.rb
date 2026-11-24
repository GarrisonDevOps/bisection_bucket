# frozen_string_literal: true

module API
  module Concerns
    module VirtualRegistries
      module SharedAuthentication
        extend ActiveSupport::Concern
        include ::API::Helpers::Authentication

        included do
          authenticate_with do |accept|
            accept.token_types(:personal_access_token)
              .sent_through(:http_private_token_header, :http_bearer_token, :private_token_param)
            accept.token_types(:job_token)
              .sent_through(:http_job_token_header, :job_token_param)
            accept.token_types(:oauth_token)
              .sent_through(:http_bearer_token, :access_token_param)
          end

          helpers do
            # Override to also allow users with the read_virtual_registry custom role
            # to find private groups. Without this, minimal-access users with only the
            # read_virtual_registry custom role get 404 from find_group! because they
            # lack read_group on private groups.
            def check_group_access(group)
              return group if can?(current_user, :read_virtual_registry, group&.virtual_registry_policy_subject)

              super
            end
          end
        end
      end
    end
  end
end
