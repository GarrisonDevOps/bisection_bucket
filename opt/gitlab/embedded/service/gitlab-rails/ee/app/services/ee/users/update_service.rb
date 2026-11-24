# frozen_string_literal: true

module EE
  module Users
    module UpdateService
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize
      include ::AuditEvents::Changes

      attr_reader :group_id_for_saml, :ldap_sync

      override :initialize
      def initialize(current_user, params = {})
        super
        @group_id_for_saml = params.delete(:group_id_for_saml)
        @ldap_sync = params.delete(:ldap_sync)
        @params = params.dup
      end

      protected

      override :entity
      def entity
        model.enterprise_group || model
      end

      private

      def notify_success(user_exists)
        notify_new_user(@user, nil) unless user_exists # rubocop:disable Gitlab/ModuleWithInstanceVariables

        audit_changes(:email, as: 'email address', event_type: 'user_email_address_updated')
        audit_changes(:encrypted_password, as: 'password', skip_changes: true, event_type: 'user_password_updated')
        audit_changes(:username, as: 'username', event_type: 'user_username_updated')
        audit_changes(:name, as: 'name', event_type: 'user_name_updated')
        audit_changes(:admin, as: 'admin status', event_type: 'user_admin_status_updated')
        audit_changes(:auditor, as: 'auditor status', event_type: 'user_auditor_status_updated')
        audit_changes(:external, as: 'external status', event_type: 'user_external_status_updated')
        audit_changes(:projects_limit, as: 'projects limit', event_type: 'user_projects_limit_updated')
        audit_changes(:can_create_group, as: 'can create group', event_type: 'user_can_create_group_updated')

        log_audit_events
      end

      def model
        @user
      end

      override :discard_read_only_attributes
      def discard_read_only_attributes
        super

        discard_name unless name_updatable?
        discard_private_profile if params[:private_profile] && !can_make_profile_private?
      end

      override :synced_attributes
      def synced_attributes
        return super unless ldap_sync

        # User email can be updated during LDAP sync if the email is updated on the LDAP server
        super - [:email]
      end

      def discard_name
        params.delete(:name)
      end

      def name_updatable?
        params.delete(:force_name_change) || can?(current_user, :update_name, model)
      end

      override :identity_params
      def identity_params
        if group_id_for_saml.present?
          super.merge(saml_provider_id: saml_provider_id)
        else
          super
        end
      end

      override :provider_attributes
      def provider_attributes
        super.push(:saml_provider_id)
      end

      override :identity_attributes
      def identity_attributes
        super.push(:saml_provider_id)
      end

      override :assign_attributes
      def assign_attributes
        params.reject! { |key, _| SamlProvider::USER_ATTRIBUTES_LOCKED_FOR_MANAGED_ACCOUNTS.include?(key.to_sym) } if model.group_managed_account?
        super
      end

      def saml_provider_id
        strong_memoize(:saml_provider_id) do
          if group_id_for_saml.present?
            group = GroupFinder.new(current_user).execute(id: group_id_for_saml)
            group&.saml_provider&.id
          end
        end
      end

      def log_audit_events
        ::Users::UserSettingChangesAuditor.new(current_user).execute
      end

      def discard_private_profile
        params.delete(:private_profile)
      end

      def can_make_profile_private?
        can?(current_user, :make_profile_private, model)
      end
    end
  end
end
