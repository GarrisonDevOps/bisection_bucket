# frozen_string_literal: true

module EE
  module Projects
    module AutocompleteSourcesController
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      prepended do
        feature_category :portfolio_management, [:epics]
        feature_category :team_planning, [:iterations]
        feature_category :vulnerability_management, [:vulnerabilities]
        urgency :low, [:epics, :iterations, :vulnerabilities]
      end

      override :issues
      def issues
        if project.group&.allow_group_items_in_project_autocompletion?
          render json: issuable_serializer.represent(
            autocomplete_service.issues,
            parent: project
          )
        else
          super
        end
      end

      def epics
        return render_404 unless project&.group&.licensed_feature_available?(:epics)

        render json: issuable_serializer.represent(
          autocomplete_service.epics,
          parent: project.group
        )
      end

      def iterations
        return render_404 unless project.group.licensed_feature_available?(:iterations)

        render json: iteration_serializer.represent(autocomplete_service.iterations)
      end

      def vulnerabilities
        return render_404 unless project.feature_available?(:security_dashboard)

        render json: autocomplete_service.vulnerabilities
      end

      private

      def iteration_serializer
        ::Autocomplete::IterationSerializer.new
      end
    end
  end
end
