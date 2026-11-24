# frozen_string_literal: true

module Gitlab
  module Llm
    class CompletionsFactory
      def self.completion!(prompt_message, options = {})
        features_list = ::Gitlab::Llm::Utils::AiFeaturesCatalogue::LIST
        name = prompt_message.ai_action.to_sym
        raise NameError, "completion class for action #{name} not found" unless features_list.key?(name)

        feature = features_list[name]
        service_class =
          if feature[:aigw_service_class] && Feature.enabled?(:"prompt_migration_#{name}", prompt_message.user)
            feature[:aigw_service_class]
          else
            feature[:service_class]
          end

        service_class.new(prompt_message, feature[:prompt_class], options.merge(action: name))
      end
    end
  end
end

::Gitlab::Llm::CompletionsFactory.prepend_mod
