# frozen_string_literal: true

module API
  module Sbom
    # NOTE: The `occurrences/vulnerabilities` endpoint is no longer consumed by the
    # frontend (the dependency list now fetches occurrence vulnerabilities via GraphQL).
    # It is retained because it is part of the public REST API and must go through the
    # formal API deprecation process before removal.
    # See: https://docs.gitlab.com/development/deprecation_guidelines/
    class Occurrences < ::API::Base
      feature_category :dependency_management
      urgency :low

      LIMIT = 100

      helpers do
        include Gitlab::Utils::StrongMemoize

        def project
          ::Sbom::Occurrence.find(params[:id]).project
        end
        strong_memoize_attr :project

        def vulnerabilities
          Vulnerability.id_in(
            ::Sbom::OccurrencesVulnerability
              .for_occurrence_ids(params[:id])
              .select(:vulnerability_id).limit(LIMIT).ordered_by_vulnerability).with_findings
        end
        strong_memoize_attr :vulnerabilities
      end

      params do
        requires :id, type: String, desc: 'ID of the occurrence.'
      end
      resource :occurrences do
        before do
          authenticate!
          authorize! :read_security_resource, project
        end

        desc 'Get vulnerabilities' do
          detail 'Returns vulnerabilities related to an occurrence.'
          tags ['dependency_management']
        end
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :read_sbom_occurrence, boundary_type: :project,
          boundary: -> { project }
        get 'vulnerabilities' do
          options = { occurrence_id: params[:id], project: project }

          present ::API::Entities::DependenciesVulnerabilities.represent(vulnerabilities, options)
        end
      end
    end
  end
end
