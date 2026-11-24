# frozen_string_literal: true

module EE
  module Users
    module BuildService
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize

      attr_reader :group_id_for_saml

      GROUP_SAML_PROVIDER = 'group_saml'
      GROUP_SCIM_PROVIDER = 'group_scim'

      override :initialize
      def initialize(current_user, params = {})
        super
        @group_id_for_saml = params.delete(:group_id_for_saml)
      end

      override :execute
      def execute
        super

        build_smartcard_identity if ::Gitlab::Auth::Smartcard.enabled?
        set_pending_approval_state

        user
      end

      private

      override :signup_params
      def signup_params
        super + name_params
      end

      def name_params
        [
          :first_name,
          :last_name
        ]
      end

      override :build_user_params_for_non_admin
      def build_user_params_for_non_admin
        super

        @user_params[:avatar] = params[:avatar] if service_account? # rubocop:disable Gitlab/ModuleWithInstanceVariables -- Using existing instance variable
      end

      override :admin_create_params
      def admin_create_params
        super + [:auditor, :composite_identity_enforced]
      end

      override :identity_attributes
      def identity_attributes
        super.push(:saml_provider_id)
      end

      override :build_identity
      def build_identity
        return super unless params[:provider] == GROUP_SCIM_PROVIDER

        build_group_scim_identity
        identity_params[:provider] = GROUP_SAML_PROVIDER

        user.provisioned_by_group_id = params[:group_id]
        user.provisioned_by_project_id = params[:project_id]

        super
      end

      override :identity_params
      def identity_params
        if group_id_for_saml.present?
          super.merge(saml_provider_id: saml_provider_id)
        else
          super
        end
      end

      def scim_identity_attributes
        [:group_id, :extern_uid]
      end

      def saml_provider_id
        strong_memoize(:saml_provider_id) do
          group = GroupFinder.new(current_user).execute(id: group_id_for_saml)
          group&.saml_provider&.id
        end
      end

      def build_smartcard_identity
        smartcard_identity_attrs = params.slice(:certificate_subject, :certificate_issuer)

        return if smartcard_identity_attrs.empty?

        user.smartcard_identities.build(subject: params[:certificate_subject], issuer: params[:certificate_issuer])
      end

      def build_group_scim_identity
        scim_identity_params = params.slice(*scim_identity_attributes)

        user.group_scim_identities.build(scim_identity_params.merge(active: true))
      end

      def set_pending_approval_state
        return unless ::User.user_cap_reached?

        if ::Feature.enabled?(:activate_nonbillable_users_over_instance_user_cap, type: :wip)
          return unless will_be_billable?(user)
        else
          return unless user.human?
        end

        user.state = ::User::BLOCKED_PENDING_APPROVAL_STATE
      end

      def will_be_billable?(user)
        user.human? && (all_humans_are_billable? || user.pending_billable_invitations.any?)
      end

      def all_humans_are_billable?
        !::License.current.exclude_guests_from_active_count?
      end
    end
  end
end
