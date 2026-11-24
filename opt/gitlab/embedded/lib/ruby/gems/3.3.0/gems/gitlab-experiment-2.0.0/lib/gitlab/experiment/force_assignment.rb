# frozen_string_literal: true

module Gitlab
  class Experiment
    module ForceAssignment
      PARAM_NAME = 'glex_force'

      private

      def forced_variant_name
        return unless Configuration.allow_forced_assignment
        return unless enabled?

        param = context&.request&.params.try(:[], PARAM_NAME)
        return if param.blank?

        experiment_name, variant_name = param.split(':', 2)
        return if experiment_name.blank? || variant_name.blank?
        return unless experiment_name == name

        variant_sym = variant_name.to_sym
        return unless behaviors.key?(variant_sym)

        variant_sym
      end
    end
  end
end
