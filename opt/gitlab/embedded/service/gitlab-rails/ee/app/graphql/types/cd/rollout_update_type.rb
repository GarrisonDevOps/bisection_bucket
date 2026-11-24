# frozen_string_literal: true

module Types
  module Cd
    # rubocop:disable Graphql/AuthorizeTypes -- subscription payload envelope; the subscription authorizes the
    # application, and the nested types authorize themselves
    class RolloutUpdateType < ::Types::BaseObject
      graphql_name 'CdRolloutUpdate'
      description 'Live rollout update pushed to the client: new deployment status, ' \
        'and a Duo session to open when one applies.'

      # The subscription (Subscriptions::Cd::RolloutUpdated#authorized?) gates delivery of the
      # whole payload against `read_cd_application`; the nested fields authorize themselves.
      authorize_granular_token skip_reason: :parent_authorizes

      field :rollout, ::Types::Cd::RolloutType,
        null: false,
        description: 'Rollout the update is for.'

      field :rollout_environment, ::Types::Cd::RolloutEnvironmentType,
        null: true,
        description: 'Rollout environment whose state changed. ' \
          'Read its state and environment.tier to color the stage dot.'

      field :thread, ::Types::Ai::Conversations::ThreadType,
        null: true,
        description: 'Duo session to open in the sidebar for the update, when one applies.'

      field :reason, ::Types::Cd::RolloutUpdateReasonEnum,
        null: true,
        description: 'Why Duo should engage for the update (failed or created); null for a plain status update.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
