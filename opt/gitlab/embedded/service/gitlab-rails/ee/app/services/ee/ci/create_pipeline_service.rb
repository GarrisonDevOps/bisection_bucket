# frozen_string_literal: true

module EE
  module Ci
    module CreatePipelineService
      extend ::Gitlab::Utils::Override

      override :extra_options
      def extra_options(mirror_update: false, **options)
        options.merge(mirror_update: mirror_update)
      end

      private

      override :after_successful_creation_hook
      def after_successful_creation_hook
        super

        track_secrets_usage
      end

      def track_secrets_usage
        return unless project&.feature_available?(:ci_secrets_management)

        root_ancestor_id = project.namespace.root_ancestor.id
        builds = pipeline.builds.includes(:job_definition, :user, project: :namespace) # rubocop:disable CodeReuse/ActiveRecord -- preload to avoid N+1 in track_ci_secrets_management_usage
        builds.each { |build| build.track_ci_secrets_management_usage(root_ancestor_id: root_ancestor_id) }
      end

      override :validate_options!
      def validate_options!(options)
        return unless params[:partition_id] && !options[:pipeline_policy_context]

        raise ArgumentError, "Param `partition_id` is only allowed with `pipeline_policy_context`"
      end
    end
  end
end
