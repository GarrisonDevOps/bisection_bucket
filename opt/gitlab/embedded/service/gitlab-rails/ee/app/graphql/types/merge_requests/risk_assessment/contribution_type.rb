# frozen_string_literal: true

module Types
  module MergeRequests
    module RiskAssessment
      # rubocop:disable Graphql/AuthorizeTypes -- authorized through the merge request that owns the assessment
      class ContributionType < BaseObject
        graphql_name 'MergeRequestRiskContribution'
        description 'Contribution a signal or a risk domain made to a merge request risk score.'

        authorize_granular_token skip_reason: :parent_authorizes

        PresentedContribution = Struct.new(:kind, :description, keyword_init: true)

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        def self.domain_names
          @domain_names ||= ::Gitlab::Duo::RiskAssessment::Domain.all.map(&:name)
        end

        field :kind, ContributionKindEnum,
          null: false,
          scopes: [:api, :read_api, :ai_workflows],
          description: 'Whether the contribution came from a signal or a risk domain.'

        field :identifier, GraphQL::Types::String,
          null: false,
          hash_key: 'signal',
          scopes: [:api, :read_api, :ai_workflows],
          description: 'Name of the signal or risk domain.'

        field :description, GraphQL::Types::String,
          null: true,
          scopes: [:api, :read_api, :ai_workflows],
          description: 'Human-readable name of the signal or risk domain.'

        field :evidence, GraphQL::Types::String,
          null: true,
          hash_key: 'detail',
          scopes: [:api, :read_api, :ai_workflows],
          description: 'Human-readable explanation of the contribution.'

        field :contribution, GraphQL::Types::Float,
          null: false,
          scopes: [:api, :read_api, :ai_workflows],
          description: 'Points the signal or risk domain added to the overall score.'

        def kind
          presented_object.kind
        end

        def description
          presented_object.description
        end

        private

        def presented_object
          @presented_object ||=
            if self.class.domain_names.include?(object['signal'])
              PresentedContribution.new(
                kind: 'domain',
                description: ::Gitlab::Duo::RiskAssessment::Domain.description_for(object['signal'])
              )
            else
              PresentedContribution.new(
                kind: 'signal',
                description: ::Gitlab::Duo::RiskAssessment::SignalsExtractor.label_for(object['signal']) ||
                  object['signal']
              )
            end
        end
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
