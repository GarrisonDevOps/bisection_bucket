# frozen_string_literal: true

module Resolvers
  module Ai
    module SelfHostedModels
      class SelfHostedModelsResolver < BaseResolver
        type ::Types::Ai::SelfHostedModels::SelfHostedModelType.connection_type, null: false

        def resolve(**args)
          return unless Ability.allowed?(current_user, :manage_self_hosted_models_settings)

          return get_self_hosted_model(args[:id]) if args[:id]

          if beta_models_enabled?
            ::Ai::SelfHostedModel.all
          else
            ::Ai::SelfHostedModel.ga_models
          end
        end

        private

        def get_self_hosted_model(self_hosted_model_gid)
          [::Ai::SelfHostedModel.find(self_hosted_model_gid.model_id)]
        end

        def beta_models_enabled?
          ::Ai::TestingTermsAcceptance.has_accepted?
        end
      end
    end
  end
end
