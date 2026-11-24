# frozen_string_literal: true

module Gitlab
  module Auth
    module GroupSaml
      class User < Gitlab::Auth::OAuth::User
        include ::Gitlab::Utils::StrongMemoize
        extend ::Gitlab::Utils::Override

        attr_accessor :saml_provider
        attr_reader :auth_hash

        override :initialize
        def initialize(auth_hash, user_params = {})
          @user_params = user_params
          @auth_hash = AuthHash.new(auth_hash)
          @new_user_was_built = false
        end

        override :find_and_update!
        def find_and_update!
          add_or_update_identity_for_enterprise_user!

          save("GroupSaml Provider ##{@saml_provider.id}")

          if valid_sign_in?
            associate_new_user_with_enterprise_group
            update_enterprise_user_attributes
            update_group_membership
            finish_onboarding
            update_duo_add_on_assignment
          end

          gl_user
        end

        override :bypass_two_factor?
        def bypass_two_factor?
          false
        end

        override :signup_identity_verification_enabled?
        def signup_identity_verification_enabled?(_)
          false
        end

        private

        override :gl_user
        def gl_user
          strong_memoize(:gl_user) do
            identity&.user || find_enterprise_user_by_email || build_new_user
          end
        end

        def identity
          strong_memoize(:identity) do
            ::Auth::GroupSamlIdentityFinder.new(saml_provider, auth_hash).first
          end
        end

        def finish_onboarding
          # We only need to finish onboarding for existing saml users since we skip
          # starting onboarding for new users in the callbacks controller.
          # We also let enterprise groups/user process handle finishing onboarding
          # separately, so we can focus only on saml here.
          return unless identity&.user

          Onboarding::FinishService.new(gl_user).execute
        end

        def find_enterprise_user_by_email
          user = find_by_email

          return unless user&.enterprise_user_of_group?(saml_provider.group)

          user
        end

        override :build_new_user
        def build_new_user(skip_confirmation: false)
          @new_user_was_built = true

          super.tap do |user|
            user.provisioned_by_group_id = saml_provider.group_id
          end
        end

        def created_new_user?
          @new_user_was_built && persisted?
        end

        override :user_attributes
        def user_attributes
          super.tap do |hash|
            hash[:extern_uid] = auth_hash.uid
            hash[:saml_provider_id] = @saml_provider.id
            hash[:provider] = ::Users::BuildService::GROUP_SAML_PROVIDER
            hash[:group_id] = saml_provider.group_id
          end
        end

        def add_or_update_identity_for_enterprise_user!
          return unless gl_user.enterprise_user_of_group?(saml_provider.group)
          return if self.identity # extern_uid hasn't changed

          # find_or_initialize_by doesn't update `gl_user.identities`, and isn't autosaved.
          identity = gl_user.identities.find { |identity| identity.provider == auth_hash.provider && identity.saml_provider_id == @saml_provider.id }
          identity ||= gl_user.identities.build(provider: auth_hash.provider, saml_provider: @saml_provider)

          identity.extern_uid = auth_hash.uid

          identity
        end

        def associate_new_user_with_enterprise_group
          return unless created_new_user?

          Groups::EnterpriseUsers::AssociateService.new(group: saml_provider.group, user: gl_user).execute
        end

        def update_enterprise_user_attributes
          EnterpriseUserAttributesUpdater.new(gl_user, saml_provider.group, auth_hash).execute
        end

        def update_group_membership
          MembershipUpdater.new(gl_user, saml_provider, auth_hash).execute
        end

        def update_duo_add_on_assignment
          DuoAddOnAssignmentUpdater.new(gl_user, saml_provider.group, auth_hash).execute
        end

        override :block_after_signup?
        def block_after_signup?
          false
        end
      end
    end
  end
end
