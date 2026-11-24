# frozen_string_literal: true

class DependencyEntity < Grape::Entity
  include RequestAwareEntity
  include DependencyMalwareGating

  class AncestorEntity < Grape::Entity
    expose :name, :version

    def name
      object[:name] || object["name"]
    end

    def version
      object[:version] || object["version"]
    end
  end

  class LocationEntity < Grape::Entity
    expose :blob_path, :path, :top_level
    expose :ancestors, using: AncestorEntity do |location|
      location[:ancestors].map(&:compact).reject(&:empty?)
    end
  end

  class VulnerabilityEntity < Grape::Entity
    expose :severity, :id
    expose :title, as: :name
    expose :url do |vulnerability, options|
      # Use options[:project] instead of vulnerability.project to avoid N+1 queries.
      # If options[:project] is nil, an error will be raised.
      ::Gitlab::Routing.url_helpers.project_security_vulnerability_url(options[:project], vulnerability)
    end
  end

  class LicenseEntity < Grape::Entity
    expose :spdx_identifier, if: ->(_) { spdx_identifier? }
    expose :name, :url

    def spdx_identifier
      object[:spdx_identifier] || object["spdx_identifier"]
    end

    def name
      object[:name] || object["name"]
    end

    def url
      object[:url] || object["url"]
    end

    private

    def spdx_identifier?
      object.key?(:spdx_identifier) || object.key?("spdx_identifier")
    end
  end

  expose :name, :packager, :version
  expose :location, using: LocationEntity, if: ->(_) { !group? }
  expose :has_dependency_paths?, as: :has_dependency_paths, if: ->(_) { !group? }
  expose :vulnerabilities, using: VulnerabilityEntity, if: ->(_) { render_vulnerabilities? }
  expose :malware,
    documentation: {
      type: 'Boolean',
      desc: 'Malware status: true if the package version matches a malware advisory, ' \
        'false otherwise. Omitted when malware detection is not enabled for the ' \
        'project or group.'
    },
    if: ->(_) { render_malware_field? } do |occurrence, _opts|
    occurrence.malware_status
  end
  expose :policy_dismissals, using: Security::PolicyDismissalEntity, if: ->(_) { group? && can_read_security_resource? }
  expose :licenses, using: LicenseEntity, if: ->(_) { can_read_licenses? } do |occurrence|
    apply_license_overrides(occurrence)
  end
  expose :occurrence_count, if: ->(_) { group? } do |object|
    object.respond_to?(:occurrence_count) ? object.occurrence_count : 1
  end
  expose :project_count, if: ->(_) { group? } do |object|
    object.respond_to?(:project_count) ? object.project_count : 1
  end
  expose :component_version_id, as: :component_id, if: ->(_) { group? }

  expose :id, as: :occurrence_id
  expose :vulnerability_count

  private

  def render_vulnerabilities?
    options[:include_vulnerabilities] && can_read_vulnerabilities?
  end

  def can_read_vulnerabilities?
    can?(request.user, :read_security_resource, subject)
  end

  def can_read_security_resource?
    can?(request.user, :read_security_resource, subject)
  end

  def can_read_licenses?
    can?(request.user, :read_licenses, subject)
  end

  def group?
    request.try(:group).present?
  end

  def apply_license_overrides(occurrence)
    applicator = options[:license_override_applicator] || request.try(:license_override_applicator)
    return occurrence.licenses unless applicator

    purl = occurrence.try(:purl)&.to_s
    applicator.apply(occurrence.licenses || [], purl: purl)
  end
end
