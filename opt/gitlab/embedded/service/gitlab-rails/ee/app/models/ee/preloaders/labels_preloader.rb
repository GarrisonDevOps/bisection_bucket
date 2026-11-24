# frozen_string_literal: true

module EE
  module Preloaders
    module LabelsPreloader
      extend ::Gitlab::Utils::Override

      override :preload_all
      def preload_all
        super

        ActiveRecord::Associations::Preloader.new(
          records: group_labels,
          associations: { group: [:ip_restrictions, :saml_provider] }
        ).call

        ActiveRecord::Associations::Preloader.new(
          records: project_labels,
          associations: { project: [:group, :invited_groups] }
        ).call

        # Preload the root ancestors for the authorization checks. The two lists hold different
        # instances of a shared group, and the preloader drops duplicates by id, so run it per list.
        group_lists = [group_labels.filter_map(&:group), project_labels.filter_map(&:project).filter_map(&:group)]
          .reject(&:empty?)

        return if group_lists.empty?

        group_lists.each { |groups| ::Namespaces::Preloaders::GroupRootAncestorPreloader.new(groups).execute }
        groups = group_lists.flatten

        ActiveRecord::Associations::Preloader.new(
          records: groups.map(&:root_ancestor),
          associations: [:saml_provider]
        ).call
      end
    end
  end
end
