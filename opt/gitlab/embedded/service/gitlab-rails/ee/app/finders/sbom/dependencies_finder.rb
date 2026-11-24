# frozen_string_literal: true

module Sbom
  class DependenciesFinder
    include Gitlab::Utils::StrongMemoize

    FILTER_PACKAGE_MANAGERS_VALUES = %w[
      bundler
      yarn
      npm
      pnpm
      bun
      maven
      composer
      pip
      conan
      go
      nuget
      sbt
      gradle
      pipenv
      poetry
      setuptools
      apk
      conda
      pub
      cargo
    ].freeze

    # @param dependable [Group, Project, Vulnerability] the container for detected SBoM occurrences
    def initialize(dependable, current_user: nil, params: {})
      @dependable = dependable
      @current_user = current_user
      @params = params
    end

    def execute
      return Sbom::Occurrence.none if non_admin_user?

      @collection = occurrences
      filter_by_source_types
      filter_by_package_managers
      filter_by_component_names
      filter_by_component_ids
      filter_by_licences
      filter_by_component_versions
      filter_by_dismissed_policies
      sort
    end

    private

    attr_reader :current_user, :dependable, :params

    def filter_by_source_types
      return if params[:source_types].blank?

      params[:source_types].map! { |e| e == 'nil_source' ? nil : e }

      @collection = @collection.filter_by_source_types(params[:source_types])
    end

    def filter_by_package_managers
      return if params[:package_managers].blank?

      @collection = @collection.filter_by_package_managers(params[:package_managers])
    end

    def filter_by_component_names
      return if params[:component_names].blank?

      @collection = @collection.filter_by_component_names(params[:component_names])
    end

    def filter_by_component_ids
      return if params[:component_ids].blank?

      @collection = @collection.filter_by_component_ids(params[:component_ids])
    end

    def filter_by_licences
      return if params[:licenses].blank?

      @collection = @collection.by_licenses(params[:licenses])
    end

    def filter_by_component_versions
      negated_filter = params[:not]

      return if params[:component_versions].blank? && negated_filter.nil?

      if params[:component_versions]
        @collection = @collection.filter_by_component_versions(params[:component_versions])
      elsif negated_filter && negated_filter[:component_versions]
        @collection = @collection.filter_by_non_component_versions(negated_filter[:component_versions])
      end
    end

    def filter_by_dismissed_policies
      return if params[:policy_violations].blank?

      # Using map here as `pluck` would not work due to usage of `DISTINCT` ON pluck_license_occurrence_uuid
      dismissed_uuids = ::Security::PolicyDismissal
                          .for_license_occurrence_uuids(@collection.map(&:uuid))
                          .pluck_license_occurrence_uuid

      @collection = Sbom::Occurrence.none if dismissed_uuids.blank?

      @collection = @collection.by_uuids(dismissed_uuids)
    end

    def sort_direction
      params[:sort]&.downcase == 'desc' ? 'desc' : 'asc'
    end

    def sort
      case params[:sort_by]
      when 'name'
        @collection.order_by_component_name(sort_direction)
      when 'packager'
        @collection.order_by_package_name(sort_direction)
      when 'license'
        @collection.order_by_spdx_identifier(sort_direction)
      when 'severity'
        @collection.order_by_severity(sort_direction)
      else
        @collection.order_by_id
      end
    end

    def occurrences
      return dependable.sbom_occurrences.for_project(dependable) if project?
      return dependable.sbom_occurrences if vulnerability?
      return dependable.sbom_occurrences if params[:project_ids].blank?

      project_ids = []

      project_ids_in_group_hierarchy.each_batch(of: 500) do |batch|
        project_ids += batch.pluck_primary_key
      end

      Sbom::Occurrence.by_project_ids(project_ids)
    end

    def project_ids_in_group_hierarchy
      Project
        .id_in(params[:project_ids])
        .for_group_and_its_subgroups(dependable)
        .select(:id)
    end

    def non_admin_user?
      current_user && !current_user.can_read_all_resources?
    end

    def project?
      dependable.is_a?(::Project)
    end

    def vulnerability?
      dependable.is_a?(::Vulnerability)
    end
  end
end
