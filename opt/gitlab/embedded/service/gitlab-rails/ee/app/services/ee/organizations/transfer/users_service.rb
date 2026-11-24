# frozen_string_literal: true

module EE
  module Organizations
    module Transfer
      module UsersService
        extend ::Gitlab::Utils::Override

        private

        override :update_personal_snippet_notes
        def update_personal_snippet_notes(user_ids)
          super

          transfer_snippet_repository_states(user_ids)
          transfer_ai_conversation_messages(user_ids)
        end

        # rubocop:disable CodeReuse/ActiveRecord -- https://docs.gitlab.com/development/database/efficient_in_operator_queries/
        def transfer_ai_conversation_messages(user_ids)
          batch_size = ::Organizations::Transfer::Concerns::OrganizationUpdater::ORGANIZATION_ID_UPDATE_BATCH_SIZE
          thread_table = ::Ai::Conversation::Thread.arel_table

          iterator = ::Gitlab::Pagination::Keyset::Iterator.new(
            scope: ::Ai::Conversation::Thread.order(:id),
            in_operator_optimization_options: {
              array_scope: ::User.id_in(user_ids).select(:id),
              array_mapping_scope: ->(user_id_expression) do
                ::Ai::Conversation::Thread.where(thread_table[:user_id].eq(user_id_expression))
              end
            }
          )

          iterator.each_batch(of: batch_size) do |threads|
            ::Ai::Conversation::Message
              .where(organization_id: old_organization.id)
              .where(thread_id: threads.map(&:id))
              .each_batch(of: batch_size) do |messages|
                messages.update_all(organization_id: new_organization.id)
              end
          end
        end
        # rubocop:enable CodeReuse/ActiveRecord

        # rubocop:disable CodeReuse/ActiveRecord -- Query specific to this service
        def transfer_snippet_repository_states(user_ids)
          personal_snippets = ::PersonalSnippet.where(author_id: user_ids)

          update_organization_id_for(
            ::Geo::SnippetRepositoryState, organization_key: :snippet_organization_id
          ) do |relation|
            # `snippet_repositories` has no `id` column of its own - its primary key is
            # `snippet_id`, shared 1:1 with `snippets.id`. So `snippet_repository_id` here
            # is directly comparable to `snippets.id`, with no join through SnippetRepository needed.
            relation.where(snippet_repository_id: personal_snippets.select(:id))
          end
        end

        override :update_personal_snippet_uploads
        def update_personal_snippet_uploads(user_ids)
          personal_snippets = ::PersonalSnippet.where(author_id: user_ids)

          update_organization_id_for(::Geo::PersonalSnippetUpload) do |relation|
            relation.where(model_id: personal_snippets)
          end

          update_organization_id_for(::Geo::PersonalSnippetUploadState) do |relation|
            relation.where(personal_snippet_upload_id: ::Geo::PersonalSnippetUpload.where(model_id: personal_snippets))
          end
        end

        override :update_abuse_reports
        def update_abuse_reports(user_ids)
          super

          transfer_abuse_report_upload_states(user_ids)
        end

        def transfer_abuse_report_upload_states(user_ids)
          report_ids = ::AbuseReport
            .by_reporter_id(user_ids)
            .where(organization_id: new_organization.id)
            .select(:id)

          upload_ids = ::AntiAbuse::AbuseReportUpload
            .where(model_id: report_ids, organization_id: new_organization.id)
            .select(:id)

          update_organization_id_for(::Geo::AbuseReportUploadState) do |relation|
            relation.where(abuse_report_upload_id: upload_ids)
          end
        end

        # Sets organization_id directly; the sharding-key trigger only backfills NULLs, so it
        # won't resync an existing row.
        override :transfer_ee_associations
        def transfer_ee_associations(user_ids)
          update_organization_id_for(::Geo::UserUpload) do |relation|
            relation.where(model_id: user_ids)
          end

          update_organization_id_for(::Geo::UserUploadState) do |relation|
            relation.where(user_upload_id: ::Geo::UserUpload.where(model_id: user_ids))
          end

          transfer_ai_token_daily_usages(user_ids)
        end

        # Rows under a group's chain move with the group in GroupsService. Rows under a personal
        # namespace move with its owner, and rows with no chain move with their user.
        def transfer_ai_token_daily_usages(user_ids)
          ::Ai::TokenDailyUsage.transfer_organization(
            ::Ai::TokenDailyUsage.where(user_id: user_ids, traversal_ids: []),
            from: old_organization.id, to: new_organization.id
          )

          user_namespaces(user_ids).ids.each do |user_namespace_id|
            ::Ai::TokenDailyUsage.transfer_organization(
              ::Ai::TokenDailyUsage.within([user_namespace_id]),
              from: old_organization.id, to: new_organization.id
            )
          end
        end
        # rubocop:enable CodeReuse/ActiveRecord
      end
    end
  end
end
