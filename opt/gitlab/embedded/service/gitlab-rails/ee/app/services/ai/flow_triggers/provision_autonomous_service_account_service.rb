# frozen_string_literal: true

module Ai
  module FlowTriggers
    # Provisions a service account dedicated to one autonomous trigger.
    #
    # Catalog-backed triggers normally share the item consumer's service
    # account. Autonomous triggers cannot, because they need composite identity
    # cleared and that flag is per account: clearing it on the shared account
    # would break every interactive trigger on the same flow. A dedicated
    # account keeps the shared one untouched.
    class ProvisionAutonomousServiceAccountService
      # Room for the numeric suffix uniquify_provided_username may append.
      MAX_USERNAME_LENGTH = ::User::MAX_USERNAME_LENGTH - 10

      # Nothing was created, so a caller inside a transaction may carry on without it.
      ERROR_REASON_NOT_PROVISIONED = :account_not_provisioned
      # The account exists but could not join the project. A caller inside a
      # transaction has to roll back, or the account outlives the failed trigger.
      ERROR_REASON_MEMBERSHIP_FAILED = :membership_failed

      # access_level: the role the account joins the project with. Callers pass
      # the flow's own role so an unattended run has exactly the access the
      # flow it runs has, no more.
      #
      # audit: pass false when the item consumer is not persisted yet, so the
      # caller can emit the event once it can report a real item_consumer_id.
      def initialize(
        project:, current_user:, item_consumer:, description:, access_level:, audit: true, kind: 'Scheduled'
      )
        @project = project
        @current_user = current_user
        @item_consumer = item_consumer
        @description = description
        @access_level = access_level
        @audit = audit
        @kind = kind
      end

      def execute
        return not_provisioned('Project is required') unless project

        unless assignable_access_level?
          return not_provisioned(
            "Access level #{access_level.inspect} cannot be granted to an autonomous service account"
          )
        end

        unless can_create_account?
          return not_provisioned('Scheduled automations run as their own service account, and you do not ' \
            'have permission to create one in this project')
        end

        unless can_add_account_to_project?
          return not_provisioned('Scheduled automations run as their own service account, and you do not ' \
            'have permission to add one to this project')
        end

        # The account only bypasses a group membership lock when composite identity is
        # enforced, which autonomous SAs never has. Refuse before creating one we cannot use.
        if project.membership_locked_for?(current_user, service_account: true)
          return not_provisioned(
            'The service account for a scheduled automation cannot be added as a member of this project'
          )
        end

        group = provisioning_group
        return not_provisioned('Project must belong to a group') unless group

        response = create_service_account(group)
        return not_provisioned(response.message) if response.error?

        service_account = response.payload[:user]

        membership_error = add_to_project(service_account)
        return membership_error if membership_error

        audit_provisioning(service_account) if @audit

        ServiceResponse.success(payload: { service_account: service_account })
      end

      private

      attr_reader :project, :current_user, :item_consumer, :description, :access_level, :kind

      # add_member enforces can_assign_role? itself, but checking here too keeps a level we
      # already know is unusable from creating an account first and rolling it back.
      def assignable_access_level?
        return false if access_level == ::Gitlab::Access::OWNER
        return false if ::Gitlab::Access.all_values.exclude?(access_level)

        project.can_assign_role?(current_user, access_level)
      end

      def can_create_account?
        Ability.allowed?(current_user, :create_service_account, project)
      end

      def can_add_account_to_project?
        Ability.allowed?(current_user, :invite_project_members, project)
      end

      # A personal namespace cannot own a service account, so reject it here
      # instead of letting GroupCreateService fail on a missing group.
      def provisioning_group
        namespace = item_consumer.group || item_consumer.project&.root_ancestor

        namespace if namespace.is_a?(::Group)
      end

      def create_service_account(group)
        ::Namespaces::ServiceAccounts::ProjectCreateService.new(
          current_user,
          {
            project_id: project.id,
            name: account_name,
            username: account_username(group),
            organization_id: project.organization_id,
            composite_identity_enforced: false,
            skip_ai_prefix_validation: true
          },
          uniquify_provided_username: true
        ).execute
      end

      # Returns an error response when membership fails, nil otherwise. Without
      # membership the trigger passes creation and then fails eligibility at
      # run time, so the failure has to surface here.
      def add_to_project(service_account)
        member = project.team.add_member(
          service_account, access_level, current_user: current_user
        ).presence

        return if member && member.persisted? && member.errors.empty?

        membership_failed(member&.errors&.full_messages&.to_sentence.presence ||
          'Failed to add the service account to the project')
      end

      def audit_provisioning(service_account)
        ::Ai::Catalog::ItemConsumers::ServiceAccountProvisionedAuditor.new(
          current_user: current_user,
          service_account: service_account,
          item: item_consumer.item,
          item_consumer: item_consumer
        ).audit
      end

      # User treats everything after the first space as the last name and limits that
      # part to MAX_NAME_LENGTH, so truncate that part only. The project path goes
      # first because truncation eats the tail and it is what makes each name distinct.
      def account_name
        "Duo #{"#{kind} #{project.path} #{description}"[0, ::User::MAX_NAME_LENGTH]}"
      end

      # Leave room under the 255 limit: uniquify_provided_username appends a numeric
      # suffix, so a long description shouldn't use it all up. Project path goes first
      # since truncation is right-to-left and it's what distinguishes the accounts.
      def account_username(group)
        "ai-#{kind}-#{project.path}-#{description}-#{group.name}".parameterize[0, MAX_USERNAME_LENGTH]
      end

      def not_provisioned(message)
        ServiceResponse.error(message: message, reason: ERROR_REASON_NOT_PROVISIONED)
      end

      def membership_failed(message)
        ServiceResponse.error(message: message, reason: ERROR_REASON_MEMBERSHIP_FAILED)
      end
    end
  end
end
