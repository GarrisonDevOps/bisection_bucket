# frozen_string_literal: true

module EE
  module Packages
    module Policies
      module DependencyProxy
        module GroupPolicy
          extend ActiveSupport::Concern
          extend ::Gitlab::Utils::Override

          prepended do
            with_scope :user
            condition(:auditor, score: 0) { false }

            condition(:no_active_sso_session) do
              policy_user = user.user

              ::Gitlab::Auth::GroupSaml::SessionEnforcer.new(policy_user, subject).access_restricted?
            end
          end

          # This is a copy of lookup_access_level! in ee/app/policies/ee/group_policy.rb
          override :lookup_access_level!
          def lookup_access_level!(for_any_session: false)
            if for_any_session
              return ::GroupMember::NO_ACCESS if no_active_sso_session?
            elsif needs_new_sso_session?
              return ::GroupMember::NO_ACCESS
            end

            super
          end
        end
      end
    end
  end
end
