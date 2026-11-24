# frozen_string_literal: true

module Organizations
  class TransferUsersWorker
    include ApplicationWorker

    data_consistency :sticky
    idempotent!

    feature_category :organization
    urgency :low

    defer_on_database_health_signal :gitlab_main, [:users, :namespaces, :projects], 1.minute

    def perform(args)
      new_organization = Organization.find_by_id(args['organization_id'])

      unless new_organization
        logger.error(
          structured_payload(
            message: 'User transfer to organization failed: organization not found',
            Labkit::Fields::GL_ORGANIZATION_ID => args['organization_id'],
            user_ids: args['user_ids']
          )
        )

        return
      end

      service = Transfer::UsersService.new(users: User.id_in(args['user_ids']), new_organization: new_organization)

      # Skips bot creation on an invalid transfer; #execute then rejects it.
      service.prepare_bots
      service.execute
    end
  end
end
