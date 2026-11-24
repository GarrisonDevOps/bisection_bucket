# frozen_string_literal: true

module Pages
  module Domains
    class CreateService < BaseService
      def execute
        return unless authorized?

        existing_domain = find_existing_domain

        if existing_domain
          domain = PagesDomain.new(domain: params[:domain])
          error_message = if Ability.allowed?(current_user, :update_pages, existing_domain.project)
                            "is already in use by project #{existing_domain.project.full_path}"
                          else
                            "is already in use by another project"
                          end

          domain.errors.add(:domain, error_message)
          return domain
        end

        domain = project.pages_domains.new(params)
        # rate_limited? validates before counting, so failed attempts don't count toward the limit.
        return rate_limited_domain if rate_limited?(domain)

        domain.save

        if domain.persisted?
          publish_event(domain)
          log_audit_event(domain, 'created')
        end

        domain
      end

      private

      def authorized?
        Ability.allowed?(current_user, :update_pages, project)
      end

      def find_existing_domain
        PagesDomain.find_by_domain_case_insensitive(params[:domain])
      end

      def rate_limited?(domain)
        return false unless domain.valid?

        throttled = Gitlab::ApplicationRateLimiter.throttled?(:pages_domain_create, scope: { user: current_user })
        log_rate_limited if throttled
        throttled
      end

      def log_rate_limited
        Gitlab::AuthLogger.error(
          message: 'Application_Rate_Limiter_Request',
          env: :pages_domain_create_request_limit,
          Labkit::Fields::GL_USER_ID => current_user.id,
          Labkit::Fields::GL_USER_NAME => current_user.username
        )
      end

      def rate_limited_domain
        PagesDomain.new(domain: params[:domain]).tap do |domain|
          domain.errors.add(:base, :rate_limited, message: Gitlab::ApplicationRateLimiter.throttled_error_message)
        end
      end

      def publish_event(domain)
        event = PagesDomainCreatedEvent.new(
          data: {
            project_id: project.id,
            namespace_id: project.namespace_id,
            root_namespace_id: project.root_namespace.id,
            domain_id: domain.id,
            domain: domain.domain
          }
        )

        Gitlab::EventStore.publish(event)
      end
    end
  end
end
