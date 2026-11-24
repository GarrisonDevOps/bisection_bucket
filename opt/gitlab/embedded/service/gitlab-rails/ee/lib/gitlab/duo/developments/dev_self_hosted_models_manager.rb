# frozen_string_literal: true

module Gitlab
  module Duo
    module Developments
      class DevSelfHostedModelsManager
        MODELS = [
          {
            name: "Claude Sonnet 3.7 [Bedrock]",
            model: :claude_3,
            identifier: "bedrock/us.anthropic.claude-3-7-sonnet-20250219-v1:0",
            endpoint: "http://ignorethis.com"
          },
          {
            name: "Claude Haiku 3.5 [Bedrock]",
            model: :claude_3,
            identifier: "bedrock/anthropic.claude-3-5-haiku-20241022-v1:0",
            endpoint: "http://ignorethis.com"
          },

          {
            name: "Claude Sonnet 4 [Bedrock]",
            model: :claude_3,
            identifier: "bedrock/us.anthropic.claude-sonnet-4-20250514-v1:0",
            endpoint: "http://ignorethis.com"
          },
          {
            name: "Llama 3.3 70b [Bedrock]",
            model: :llama3,
            identifier: "bedrock/us.meta.llama3-3-70b-instruct-v1:0",
            endpoint: "http://ignorethis.com"
          },
          {
            name: "Llama 3.1 8b [Bedrock]",
            model: :llama3,
            identifier: "bedrock/us.meta.llama3-1-8b-instruct-v1:0",
            endpoint: "http://ignorethis.com"
          },
          {
            name: "Llama 3.1 70b [Bedrock]",
            model: :llama3,
            identifier: "bedrock/us.meta.llama3-1-70b-instruct-v1:0",
            endpoint: "http://ignorethis.com"
          },
          {
            name: "Mistral Small [FireworksAI]",
            endpoint: "https://api.fireworks.ai/inference/v1/chat/completions",
            identifier: "fireworks_ai/accounts/gitlab/deployedModels/mistral-small-24b-instruct-2501-szc81a96",
            model: :mistral
          },
          {
            name: "Mixtral 8x22b [FireworksAI]",
            endpoint: "https://api.fireworks.ai/inference/v1/chat/completions",
            identifier: "fireworks_ai/accounts/fireworks/models/mixtral-8x22b-instruct",
            model: :mixtral
          },
          {
            name: "Codestral 22b v0.1 [FireworksAI]",
            endpoint: "https://api.fireworks.ai/inference/v1/chat/completions",
            identifier: "fireworks_ai/accounts/gitlab/deployedModels/mistralai-codestral-22b-v0p1-d8p7f3i9",
            model: :codestral
          },
          {
            name: "Llama 3.1 8b [FireworksAI]",
            endpoint: "https://api.fireworks.ai/inference/v1/chat/completions",
            identifier: "fireworks_ai/accounts/fireworks/models/llama-v3p1-8b-instruct",
            model: :llama3
          },
          {
            name: "Llama 3.1 70b [FireworksAI]",
            endpoint: "https://api.fireworks.ai/inference/v1/chat/completions",
            identifier: "fireworks_ai/accounts/fireworks/models/llama-v3p1-70b-instruct",
            model: :llama3
          },
          {
            name: "Llama 3.3 70b [FireworksAI]",
            endpoint: "https://api.fireworks.ai/inference/v1/chat/completions",
            identifier: "fireworks_ai/accounts/fireworks/models/llama-v3p3-70b-instruct",
            model: :llama3
          },
          {
            name: "Nomic Embed Text v1.5 [Fireworks AI]",
            endpoint: "https://api.fireworks.ai/inference/v1",
            identifier: "fireworks_ai/nomic-ai/nomic-embed-text-v1.5",
            model: :embedding
          }
        ].freeze

        def self.seed_models
          current_user = User.find_by_id(1)
          raise "User with ID 1 not found. Please ensure an admin user exists." unless current_user

          MODELS.each do |model|
            next if ::Ai::SelfHostedModel.find_by_name(model[:name])

            ::Ai::SelfHostedModels::CreateService.new(current_user, model).execute
          end

          puts <<~MSG
            Self-hosted models created successfully

            Use `rake gitlab:duo:list_self_hosted_models` to see the created models
            Refer to #{self_hosted_docs_url}
            for information on bedrock and fireworks authorization and AI Gateway configuration
          MSG

          list_models
        end

        def self.self_hosted_docs_url
          Rails.application.routes.url_helpers.help_page_url(
            'development/ai_features/developing_ai_features_for_duo_self_hosted.md')
        end

        def self.list_models
          puts "The following models are available"

          ::Ai::SelfHostedModel.find_each do |model|
            puts model.name
          end
        end

        def self.clean_up_duo_self_hosted
          ::Ai::FeatureSetting.delete_all
          ::Ai::SelfHostedModel.delete_all

          puts "Self-hosted models and settings cleaned up"
        end
      end
    end
  end
end
