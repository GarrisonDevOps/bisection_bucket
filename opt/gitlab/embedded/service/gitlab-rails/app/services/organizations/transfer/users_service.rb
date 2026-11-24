# frozen_string_literal: true

module Organizations
  module Transfer
    class UsersService
      include Gitlab::Utils::StrongMemoize
      include Organizations::Transfer::Concerns::OrganizationUpdater

      BATCH_SIZE = 50

      class << self
        include Gitlab::Utils::StrongMemoize

        # Ensure Rails.application.eager_load! returns true before calling this method
        def migratable_models
          ApplicationRecord.descendants.select do |model|
            !model.to_s.in?(skipped_transfer_models) &&
              model.reflect_on_all_associations.one? { |assoc| associated_class(assoc) == ::User } &&
              model.reflect_on_all_associations.one? do |assoc|
                associated_class(assoc) == ::Organizations::Organization
              end
          end
        end
        strong_memoize_attr :migratable_models

        def skipped_transfer_models
          # Kept in alphabetical order.
          [
            # AbuseReport has three User associations (reporter, user, resolved_by), so it can never
            # be auto-discovered. It follows its reporter, handled in #update_abuse_reports.
            "AbuseReport",
            "Ai::Catalog::ItemConsumer",
            # Owned by their Ai::Catalog::Item; GroupsService transfers them scoped by item.
            "Ai::Catalog::ItemStar",
            "Ai::Catalog::ItemVersion",
            # MCP servers are organization-level, so they stay when their creator moves.
            "Ai::Catalog::McpServer",
            "Ai::Catalog::McpServerBlock",
            "Ai::Catalog::McpServersUser",
            # Memory is scoped per-organization; rows stay with the old org when a user transfers.
            "Ai::OrganizationUserMemory",
            # EE moves a group's rows with the group, a personal namespace's rows with its owner,
            # and the rest with their user.
            "Ai::TokenDailyUsage",
            # AntiAbuse::Event would be auto-discovered through its only User association, the
            # reported user. Its organization_id derives from the parent report instead, so
            # #update_abuse_reports transfers it by abuse_report_id. Events with a NULL
            # abuse_report_id are not moved; the only writer,
            # AntiAbuse::SpamAbuseEventsWorker, always sets it.
            "AntiAbuse::Event",
            # Owned by its dashboard; GroupsService transfers it scoped by dashboard.
            "Analytics::CustomDashboards::DashboardVersion",
            "Authz::AdminRole",
            "Authz::GranularScope",
            "Authz::OauthApplicationGranularScope",
            "Authz::OauthConsentGrantGranularScope",
            "Authz::PersonalAccessTokenGranularScope",
            # BulkImports::Export is scoped to a project or group, so it must not follow the user
            # to a new organization, otherwise it would diverge from its project/group. The model
            # declares no organization association today, so it is already excluded; this entry
            # makes the intent explicit.
            "BulkImports::Export",
            # Cd::VersionSet derives its organization_id from its application; created_by is only
            # the author, so the version set must not follow them.
            "Cd::VersionSet",
            "Clusters::Cluster",
            # Dependencies::DependencyListExport is scoped to one of project/group/pipeline per
            # `only_one_exportable`. Its organization_id is derived from the project/group and
            # cannot be updated independently under the
            # num_nonnulls(group_id, organization_id, project_id) = 1 check constraint.
            "Dependencies::DependencyListExport",
            # OauthAccessToken subclasses Doorkeeper::AccessToken on the same table, so it moves these rows.
            "Doorkeeper::AccessToken",
            "GitlabSubscriptions::AddOnPurchase",
            "GitlabSubscriptions::SeatAssignment",
            "GitlabSubscriptions::UserAddOnAssignment",
            # Govern::PolicyEvaluation is an audit-style record sharded by its policy's
            # organization; user_id is only the evaluation principal, so a user transfer
            # must not move it.
            "Govern::PolicyEvaluation",
            "Group", # migrated by a dedicated service
            "ImportFailure",
            # Import::Sync::Repository follows the project instead of connected_by_user. It
            # declares no organization association today, so it's already excluded; this entry
            # makes the intent explicit.
            "Import::Sync::Repository",
            "MemberRole",
            # Memberships in the new organization are created by #create_new_organization_memberships;
            # moving the old rows would collide with them and carry over access levels.
            "Organizations::OrganizationUser",
            "Project", # migrated by a dedicated service
            "ProjectSnippet",
            # The mapping must stay in its agent's project's organization; creator_id is only the
            # author. GroupsService transfers it with the agent's project.
            "RemoteDevelopment::OrganizationClusterAgentMapping",
            # Owned by its report; #update_abuse_reports transfers it by abuse_report_id.
            "ResourceEvents::AbuseReportEvent",
            "Snippet",
            "User", # migrated by a dedicated service
            "Vulnerabilities::Export", # scoped to group/project; transferred by SecurityExportsService
            # Workforce::Person belongs to the tenant that imported the hierarchy, not to the
            # GitLab user it happens to be matched to. Its organization_id comes from the
            # hierarchy under the num_nonnulls(group_id, organization_id) = 1 check constraint,
            # so a user transfer must not move it.
            "Workforce::Person"
          ]
        end

        private

        # Compares resolved classes rather than class_name strings, which differ for inferred
        # names inside a namespace (e.g. 'Organization') or a leading '::'.
        def associated_class(assoc)
          return if assoc.polymorphic?

          assoc.klass
        # NameError: the class does not exist. ArgumentError: it is not a model, e.g. a
        # background migration's inline model resolving `belongs_to :group` to a non-model constant.
        rescue NameError, ArgumentError
          nil
        end
      end

      def initialize(users:, new_organization:)
        @users = users
        @new_organization = new_organization
      end

      def async_execute
        validation_error = validate
        return validation_error if validation_error

        Organizations::TransferUsersWorker.perform_async(
          {
            'user_ids' => users.ids, # rubocop:disable CodeReuse/ActiveRecord -- .ids is reasonable here
            'organization_id' => new_organization.id
          }
        )

        ServiceResponse.success(message: s_("TransferOrganization|User transfer to organization initiated"))
      end

      def execute
        validation_error = validate
        return validation_error if validation_error

        # Capture log fields before the transaction. If the transfer fails, the
        # transaction is aborted and any DB read would raise PG::InFailedSqlTransaction
        # during error logging.
        capture_log_context

        # Only create a transaction if we're not already in one
        # This allows the related organization group transfer
        # service to manage the outer transaction
        in_outer_transaction = User.connection.transaction_open?

        if in_outer_transaction
          perform_transfer
        else
          User.transaction do
            perform_transfer
          end
        end

        log_transfer_success
        ServiceResponse.success
      rescue StandardError => e
        # When in outer transaction: re-raise to propagate and trigger rollback
        # When managing own transaction: return error (transaction already rolled back)
        raise e if in_outer_transaction

        log_transfer_error(e.message)
        ServiceResponse.error(message: e.message, payload: { exception: e })
      end

      # Pre-create bot users before the transaction to avoid exclusive lease errors.
      # No-ops on an invalid transfer so it never creates bots for a transfer #execute rejects.
      def prepare_bots
        return if validate

        new_organization_bots
      end

      def can_transfer_users?
        return false unless users_belong_to_single_organization?
        return false unless old_organization.present?

        true
      end

      def transfer_error
        return organization_not_found_error unless old_organization.present?

        users_different_organizations_error unless users_belong_to_single_organization?
      end

      # rubocop:disable CodeReuse/ActiveRecord -- Query specific to this service
      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- Using batches of 50
      def users_belong_to_single_organization?
        organization_ids = users.distinct.pluck(:organization_id).compact

        # All users must belong to exactly one organization
        organization_ids.size == 1
      end
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit
      # rubocop:enable CodeReuse/ActiveRecord

      private

      attr_reader :users, :new_organization

      def validate
        return ServiceResponse.error(message: transfer_error) unless can_transfer_users?
        return ServiceResponse.error(message: already_transferred_error) if already_transferred?
        return ServiceResponse.error(message: internal_users_error) if internal_users?

        nil
      end

      def perform_transfer
        users.each_batch(of: BATCH_SIZE) do |user_batch|
          user_ids = user_batch.ids # rubocop:disable CodeReuse/ActiveRecord -- .ids is reasonable here
          next if user_ids.empty?

          update_users(user_ids)
          update_user_projects(user_ids)
          update_todos(user_ids)
          update_import_failures(user_ids)
          update_granular_scopes(user_ids)
          update_oauth_consent_grant_granular_scopes(user_ids)
          update_auth_artifacts(user_ids)
          update_associated_organization_ids(user_ids)
          update_personal_snippet_notes(user_ids)
          update_user_agent_details(user_ids)
          update_clusters(user_ids)
          update_oauth_application_granular_scopes(user_ids)
          update_oauth_applications(user_ids)
          update_abuse_reports(user_ids)
          transfer_ee_associations(user_ids)
          update_personal_snippet_uploads(user_ids)
        end
      end

      # Add simple associated organization_id updates here.
      # Use a block to define the where clause/scopes for the query.
      # `.where(organization_id: old_organization.id)` is automatically added to all queries.
      # See Organizations::Transfer::Concerns::OrganizationUpdater#update_organization_id_for for more details.
      def update_associated_organization_ids(user_ids)
        self.class.migratable_models.each do |model_class|
          user_assoc = model_class.reflect_on_all_associations.find { |assoc| assoc.class_name == "User" }

          user_key = user_assoc.foreign_key

          update_organization_id_for(model_class) do |relation|
            relation.where(user_key => user_ids) # rubocop:disable CodeReuse/ActiveRecord -- cannot guarantee each model has a specific user scope
          end
        end
      end

      def update_users(user_ids)
        User.id_in(user_ids).update_all(user_transfer_attributes)
        create_new_organization_memberships(user_ids)
        user_namespaces(user_ids).update_all(transfer_attributes)
      end

      def create_new_organization_memberships(user_ids)
        records = user_ids.map do |user_id|
          { organization_id: new_organization.id, user_id: user_id, access_level: :default }
        end

        Organizations::OrganizationUser.upsert_all(
          records,
          unique_by: [:organization_id, :user_id],
          on_duplicate: :skip
        )
      end

      # rubocop:disable CodeReuse/ActiveRecord -- Only for .ids and .pluck which are reasonable uses
      def update_user_projects(user_ids)
        user_namespace_batch_ids = user_namespaces(user_ids).ids
        projects_scope = Project.in_namespace(user_namespace_batch_ids)

        projects_scope.each_batch(of: BATCH_SIZE) do |project_batch|
          project_ids = project_batch.ids
          next if project_ids.empty?

          # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- Using batches of 50
          project_namespace_ids = project_batch.pluck(:project_namespace_id)
          # rubocop:enable Database/AvoidUsingPluckWithoutLimit

          Namespaces::ProjectNamespace.where(id: project_namespace_ids).update_all(transfer_attributes)
          Project.id_in(project_ids).update_all(transfer_attributes)
        end
      end

      def update_todos(user_ids)
        old_organization_bots.each do |user_type, old_bot|
          new_bot = new_organization_bots[user_type]

          Todo.for_author(old_bot&.id).for_user(user_ids).update_all(author_id: new_bot.id)
        end

        update_organization_id_for(Todo) do |relation|
          relation.where(user_id: user_ids)
        end
      end

      def update_import_failures(user_ids)
        update_organization_id_for(ImportFailure) do |relation|
          relation.where(user_id: user_ids)
        end
      end

      # rubocop:enable CodeReuse/ActiveRecord

      def new_organization_bots
        # rubocop:disable GitlabSecurity/PublicSend -- Safe usage
        old_organization_bots.keys.index_with do |user_type|
          ::Users::Internal.in_organization(new_organization).public_send(user_type.to_sym)
        end
        # rubocop:enable GitlabSecurity/PublicSend
      end
      strong_memoize_attr :new_organization_bots

      def old_organization
        # This is safe because can_transfer_users? ensures all users belong to the same organization
        users.pick(:organization_id).then { |id| Organizations::Organization.find_by_id(id) }
      end
      strong_memoize_attr :old_organization

      def already_transferred?
        old_organization.id == new_organization.id
      end

      # Internal users (the ghost user and organization-level bots) are looked up per organization
      # during the transfer, so they must not be moved. Service accounts and project bots are
      # genuinely user-owned and transfer correctly, so they are allowed.
      def internal_users?
        users.with_user_types(::User::INTERNAL_USER_TYPES).exists?
      end

      # These are organization-specific bots that may be the author of Todos.
      def old_organization_bots
        bot_types =
          %i[ghost support_bot alert_bot security_bot automation_bot duo_code_review_bot admin_bot orbit_bot]

        bot_types.index_with do |user_type|
          User.with_user_types(user_type).in_organization(old_organization).first
        end.compact
      end
      strong_memoize_attr :old_organization_bots

      def transfer_attributes
        {
          organization_id: new_organization.id,
          visibility_level: Arel.sql('LEAST(?, visibility_level)', new_organization.visibility_level)
        }
      end

      def user_transfer_attributes
        attrs = { organization_id: new_organization.id }
        attrs[:private_profile] = true unless new_organization.public?
        attrs
      end

      def user_namespaces(user_ids)
        Namespaces::UserNamespace.for_owner(user_ids)
      end

      # rubocop:disable CodeReuse/ActiveRecord -- Query specific to this service
      def update_granular_scopes(user_ids)
        token_ids = PersonalAccessToken.where(user_id: user_ids, organization_id: old_organization.id).select(:id)

        update_granular_scopes_through(Authz::PersonalAccessTokenGranularScope, personal_access_token_id: token_ids)
      end

      def update_oauth_consent_grant_granular_scopes(user_ids)
        grant_ids = Authz::OauthConsentGrant.where(user_id: user_ids, organization_id: old_organization.id).select(:id)

        update_granular_scopes_through(Authz::OauthConsentGrantGranularScope, oauth_consent_grant_id: grant_ids)
      end

      def update_oauth_application_granular_scopes(user_ids)
        application_ids = Authn::OauthApplication
          .owned_by_users(user_ids)
          .where(organization_id: old_organization.id)
          .select(:id)

        update_granular_scopes_through(Authz::OauthApplicationGranularScope, application_id: application_ids)
      end

      def update_granular_scopes_through(join_model, owner_condition)
        update_organization_id_for(join_model) do |relation|
          relation.where(owner_condition)
        end

        granular_scope_ids = join_model.where(owner_condition).select(:granular_scope_id)

        update_organization_id_for(Authz::GranularScope) do |relation|
          relation.where(id: granular_scope_ids)
        end
      end

      def update_personal_snippet_notes(user_ids)
        personal_snippets = PersonalSnippet.where(author_id: user_ids)

        Note
          .where(noteable: personal_snippets, organization: old_organization)
          .each_batch(of: BATCH_SIZE) do |notes_batch|
            update_attributes = note_transfer_attributes(user_ids)

            notes_batch.update_all(update_attributes)
          end

        [
          SnippetRepository,
          SnippetStatistics,
          SnippetUserMention,
          Snippets::RepositoryStorageMove
        ].each do |snippet_class|
          update_organization_id_for(snippet_class, organization_key: :snippet_organization_id) do |relation|
            relation.where(snippet_id: personal_snippets)
          end
        end
      end

      def update_user_agent_details(user_ids)
        update_organization_id_for(UserAgentDetail) do |relation|
          relation.for_subjects('Snippet', PersonalSnippet.where(author_id: user_ids).select(:id))
        end
      end

      def note_transfer_attributes(transferring_user_ids)
        table = Note.arel_table
        ghost_id = new_organization_bots[:ghost].id

        attributes = { organization_id: new_organization.id }

        %i[author_id updated_by_id resolved_by_id].each do |column|
          attributes[column] = Arel::Nodes::Case.new
            .when(table[column].eq(nil)).then(nil)
            .when(table[column].in(transferring_user_ids)).then(table[column])
            .else(ghost_id)
        end

        attributes
      end
      # rubocop:enable CodeReuse/ActiveRecord

      # rubocop:disable CodeReuse/ActiveRecord -- Query specific to this service
      def update_clusters(user_ids)
        cluster_ids = Clusters::Cluster.where(user_id: user_ids).select(:id)

        update_organization_id_for(Clusters::Cluster) do |relation|
          relation.where(id: cluster_ids)
        end

        [
          Clusters::Platforms::Kubernetes,
          Clusters::Providers::Gcp,
          Clusters::Providers::Aws,
          Clusters::KubernetesNamespace
        ].each do |model_class|
          update_organization_id_for(model_class) do |relation|
            relation.where(cluster_id: cluster_ids)
          end
        end
      end
      # rubocop:enable CodeReuse/ActiveRecord

      # rubocop:disable CodeReuse/ActiveRecord -- Query specific to this service
      # Parent PATs and access grants are looked up in the old organization, so this must run before
      # #update_associated_organization_ids moves them.
      def update_auth_artifacts(user_ids)
        update_pat_last_used_ips(user_ids)

        grant_ids = Doorkeeper::AccessGrant
          .where(resource_owner_id: user_ids, organization_id: old_organization.id)
          .select(:id)

        # ANY(ARRAY(...)) resolves the grants first; as IN, users without grants make each_batch walk the pkey.
        update_organization_id_for(Doorkeeper::OpenidConnect::Request) do |relation|
          relation.where('oauth_openid_requests.access_grant_id = ANY(ARRAY(?))', grant_ids)
        end

        update_organization_id_for(Doorkeeper::DeviceAuthorizationGrant::DeviceGrant) do |relation|
          relation.where(resource_owner_id: user_ids)
        end
      end

      # Batches over the parent PATs with keyset pagination: each_batch on the IP table orders by its
      # primary key, which the planner walks instead of using the personal_access_token_id index.
      def update_pat_last_used_ips(user_ids)
        array_scope = User.id_in(user_ids).select(:id)
        array_mapping_scope = ->(user_id_expression) do
          PersonalAccessToken.where(PersonalAccessToken.arel_table[:user_id].eq(user_id_expression))
        end
        token_scope = PersonalAccessToken.where(organization_id: old_organization.id).select(:id).order(:id)

        Gitlab::Pagination::Keyset::Iterator.new(
          scope: token_scope,
          in_operator_optimization_options: { array_scope: array_scope, array_mapping_scope: array_mapping_scope }
        ).each_batch(of: ORGANIZATION_ID_UPDATE_BATCH_SIZE) do |tokens|
          Authn::PersonalAccessTokenLastUsedIp
            .where(organization_id: old_organization.id, personal_access_token_id: tokens.map(&:id))
            .update_all(organization_id: new_organization.id)
        end
      end
      # rubocop:enable CodeReuse/ActiveRecord

      # rubocop:disable CodeReuse/ActiveRecord -- Query specific to this service
      # Abuse reports follow their reporter, matching AntiAbuse::AbuseReport::CreateService which
      # sets organization_id from params[:reporter].organization_id.
      #
      # report_ids is scoped to the old organization, so the AbuseReport update must stay last
      # here. Same ordering contract as #update_granular_scopes.
      def update_abuse_reports(user_ids)
        report_ids = AbuseReport
          .by_reporter_id(user_ids)
          .where(organization_id: old_organization.id)
          .select(:id)

        update_abuse_report_uploads(report_ids)

        update_organization_id_for(AntiAbuse::Event) do |relation|
          relation.where(abuse_report_id: report_ids)
        end

        update_organization_id_for(ResourceEvents::AbuseReportEvent) do |relation|
          relation.where(abuse_report_id: report_ids)
        end

        update_organization_id_for(AbuseReport) do |relation|
          relation.by_reporter_id(user_ids)
        end
      end

      def update_abuse_report_uploads(report_ids)
        update_organization_id_for(AntiAbuse::AbuseReportUpload) do |relation|
          relation.where(model_id: report_ids)
        end
      end
      # rubocop:enable CodeReuse/ActiveRecord

      def update_oauth_applications(user_ids)
        update_organization_id_for(Authn::OauthApplication) do |relation|
          relation.owned_by_users(user_ids)
        end
      end

      def transfer_ee_associations(user_ids); end

      def update_personal_snippet_uploads(user_ids); end

      def organization_not_found_error
        s_("TransferOrganization|Cannot transfer users because the existing organization could not be found.")
      end

      def users_different_organizations_error
        s_("TransferOrganization|Cannot transfer users to a different organization " \
          "if all users do not belong to the same organization as the top-level group.")
      end

      def already_transferred_error
        s_("TransferOrganization|Users are already in the target organization.")
      end

      def internal_users_error
        s_("TransferOrganization|Internal users such as the ghost user and bots cannot be transferred.")
      end

      # Only called after #validate passes, so old_organization is present and
      # new_organization is always set from the constructor.
      def capture_log_context
        @log_context = {
          Labkit::Fields::GL_ORGANIZATION_ID => new_organization.id,
          old_organization_id: old_organization.id,
          user_ids: users.ids # rubocop:disable CodeReuse/ActiveRecord -- .ids is reasonable here
        }
      end

      def log_transfer_success
        log_transfer
      end

      def log_transfer_error(error_message)
        log_transfer(error_message)
      end

      def log_transfer(error_message = nil)
        action = error_message.nil? ? "were" : "were not"

        log_payload = (@log_context || {}).merge(
          message: "Users #{action} transferred to a new organization",
          error_message: error_message
        )

        if error_message.nil?
          ::Gitlab::AppLogger.info(log_payload)
        else
          ::Gitlab::AppLogger.error(log_payload)
        end
      end
    end
  end
end

Organizations::Transfer::UsersService.prepend_mod
