# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class AccessType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitAccess'
        description 'Orbit access state of a group, or of the instance on GitLab Self-Managed and GitLab Dedicated.'

        include ::Gitlab::Utils::StrongMemoize

        authorize_granular_token skip_reason: :parent_authorizes

        field :state, AccessStateEnum,
          null: false,
          description: 'Access state of the group or the instance for Orbit.',
          experiment: { milestone: '19.5' }

        field :reason, AccessReasonEnum,
          null: true,
          description: 'Cause of the access state when it has more than one cause. ' \
            'Null when the state has a single cause.',
          experiment: { milestone: '19.5' }

        field :turn_on_denial_reason, TurnOnDenialReasonEnum,
          null: true,
          description: 'Reason the user cannot turn Orbit on. Null when turning on is allowed or Orbit is already on.',
          experiment: { milestone: '19.5' }

        field :trial, TrialType,
          null: true,
          description: 'Orbit trial of the group or the instance. Null outside the trial flow.',
          experiment: { milestone: '19.5' }

        delegate :state, :reason, :turn_on_denial_reason, to: :access

        def trial
          TrialType::Adapter.new(trial: access.trial, group: group) if access.trial
        end

        private

        # The parent is a group, or :instance for the access of the whole instance.
        def group
          object unless object == :instance
        end

        def access
          account = group ? ::Analytics::Orbit::Billing.account_for(group) : ::Analytics::Orbit::Billing.instance_account
          account.access(group: group, current_user: current_user)
        end
        strong_memoize_attr :access
      end
    end
  end
end
