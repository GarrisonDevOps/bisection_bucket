# frozen_string_literal: true

class DashboardEnvironmentsSerializer < BaseSerializer
  include WithPagination

  entity DashboardEnvironmentsProjectEntity

  def represent(resource, opts = {})
    resource = @paginator.paginate(resource) if paginated?

    super(batch_load(resource), opts)
  end

  private

  def batch_load(projects)
    ActiveRecord::Associations::Preloader.new(
      records: projects,
      associations: [
        :route,
        :project_feature,
        { environments_for_dashboard: [
            project: [:project_feature, :group, { namespace: :route }]
          ],
          namespace: [:route, :owner] }
      ]
    ).call

    environments = projects.flat_map(&:environments_for_dashboard)

    Preloaders::Environments::DeploymentPreloader.new(environments)
      .execute_with_union(:last_visible_deployment, deployment_associations)

    projects
  end

  def deployment_associations
    {
      deployable: {
        metadata: nil,
        pipeline: {
          user: nil,
          project: project_associations
        },
        project: project_associations
      },
      project: {
        route: nil,
        namespace: :route
      }
    }
  end

  def project_associations
    {
      project_feature: nil,
      group: nil,
      route: nil,
      namespace: :route
    }
  end
end
