# frozen_string_literal: true

module API
  module Entities
    class Experiment < Grape::Entity
      expose :key, documentation: { type: 'String', example: 'code_quality_walkthrough' } do |definition|
        experiment_name(definition)
      end

      expose :context, documentation: {
        type: 'String', is_array: true, example: %w[user],
        desc: 'Context keys the experiment declares: `user`, `namespace`, `project`, or `actor`. Empty when ' \
          'the experiment declares no context keys. ' \
          '[Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248274) in GitLab 19.3.'
      } do |definition|
        ApplicationExperiment.constantize(experiment_name(definition)).context_keys
      rescue Gitlab::AbstractMethodError, Gitlab::Experiment::UnregisteredExperiment
        []
      end

      expose :definition, using: ::API::Entities::Feature::Definition do |feature|
        ::Feature::Definition.definitions[feature.name.to_sym]
      end

      class CurrentStatus < Grape::Entity
        expose :state, documentation: { type: 'String', example: 'on' }
        expose :gates, using: ::API::Entities::FeatureGate do |model|
          model.gates.filter_map do |gate|
            # in Flipper 0.26.1, they removed two GateValues#[] method calls for performance reasons
            # https://github.com/flippercloud/flipper/pull/706/commits/ed914b6adc329455a634be843c38db479299efc7
            # https://github.com/flippercloud/flipper/commit/eee20f3ae278d168c8bf70a7a5fcc03bedf432b5
            value = model.gate_values.send(gate.key) # rubocop:disable GitlabSecurity/PublicSend

            # By default all gate values are populated. Only show relevant ones.
            next if (value.is_a?(Integer) && value == 0) || (value.is_a?(Set) && value.empty?)

            { key: gate.key, value: value }
          end.compact
        end
      end

      expose :current_status, using: ::API::Entities::Experiment::CurrentStatus do |definition|
        feature(definition)
      end

      private

      def feature(definition)
        @feature ||= ::Feature.get(definition.attributes[:name]) # rubocop:disable Gitlab/AvoidFeatureGet
      end

      # Some experiments carry extra data in their feature flag name, so the flag
      # is not named after the experiment class it belongs to. Strip that suffix to
      # get back to the name the experiment is registered under.
      def experiment_name(definition)
        definition.attributes[:name].gsub(/_experiment_percentage$/, '')
      end
    end
  end
end
